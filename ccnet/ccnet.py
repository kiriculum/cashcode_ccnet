import logging
import time

import serial

from .structs import State, Command, accepted_bills, threaded, Device, Bill


class CCNET(object):
    """CCNET protocol controller for CashCode Bill Validator"""

    busy_time = .0
    bill_table: dict[int, Bill] = {}
    sync = b'\x02'
    device_type = b'\x03'
    state = State.POWERUP
    device = Device('', '', b'')

    def __init__(self, port):
        self.connection = serial.Serial(
            port=port, baudrate=9600, timeout=None,
            bytesize=serial.EIGHTBITS, parity=serial.PARITY_NONE)

    def connect(self):
        self.connection.close()
        self.connection.open()

        self.poll()
        self.reset()
        self._wait_states(5, [State.DISABLED])
        self.identification()
        self.get_bill_table()

    def reset(self):
        self._execute(Command.RESET)
        self.poll()

    def get_status(self):
        logging.info('Get device status')
        data = self._execute(Command.GETSTATUS)
        self._execute(Command.ACK)
        logging.info(f'Status: {data}')

    def enable_bills(self, bills_enabled=accepted_bills, escrow_bills=tuple(range(24))) -> bool:
        data = 0

        for collection in [bills_enabled, escrow_bills]:
            part = 0
            for bill_number in collection:
                mask = 1
                mask <<= bill_number
                part |= mask
            part &= (1 << 24) - 1  # Check part is less than 24 bits (3 bytes)
            data |= part
            data <<= 24

        rsp = self._execute(Command.ENABLEBILLS, data.to_bytes(6, 'big'))
        if Command(rsp[0]) is not Command.ACK:
            logging.error('Got bad response for ENABLE BILLS command: ', rsp)
            self.reset()
            return False
        self.poll()
        return True

    def check_accepted_bills(self) -> bool:
        for bit, bill in accepted_bills:
            if bit not in self.bill_table or bill.amount != self.bill_table[bit].amount:
                return False
        return True

    def get_bill_table(self) -> bool:
        logging.info('Get accepted bills table')
        self.poll()
        if self.state not in [State.INITIALIZE, State.DISABLED, State.GENERICFAILED]:
            logging.error('Device not in INITIALIZE or DISABLED state')
            return False
        data = self._execute(Command.BILLTABLE)
        self._execute(Command.ACK)
        if len(data) != 120:
            logging.error('Got bad data response')
            return False
        table = {}
        for ind, word in enumerate([data[i:i + 5] for i in range(0, len(data), 5)]):
            if len(word) != 5:
                raise ValueError(f'Word of wrong length: {word}')
            cur_nom = word[0]
            cur_pow = word[4]
            table[ind] = Bill(cur_nom * 10 ** cur_pow, word[1:4].decode())
        self.bill_table = table
        return True

    def identification(self) -> bool:
        self.poll()
        if self.state not in [State.INITIALIZE, State.DISABLED, State.GENERICFAILED]:
            logging.error('Device not in INITIALIZE or DISABLED state')
            return False
        data = self._execute(Command.IDENTIFICATION)
        self._execute(Command.ACK)
        if len(data) != 34:
            return False
        self.device = Device(data[0:15].decode(), data[15:27].decode(), data[27:34])
        return True

    def stack_bill(self) -> tuple[bool, int]:
        logging.debug('Stack bill')
        return self._move_bill(Command.STACK)

    def return_bill(self) -> tuple[bool, int]:
        logging.info('Return bill')
        return self._move_bill(Command.RETURN)

    def _move_bill(self, command: Command) -> tuple[bool, int]:
        self.poll()
        if self.state not in [State.ESCROWPOSITION, State.HOLDING]:
            logging.error('Device not in ESCROW or HOLDING state')
            return False, 0
        data = self._execute(command)
        if Command(data[0:1]) is not Command.ACK:
            logging.error(f'Got bad response for {command.name} command: ', data)
            return False, 0
        self._wait_states(timeout=30, states=[State.BILLRETURNED])
        if self.state is not State.BILLRETURNED:
            logging.error(f'Have not got BILL {command.name} state')
            return False, 0
        self.poll()
        return True, data[1]

    def poll(self) -> None:
        data = self._execute(Command.POLL)
        self.state = State(data[0:1])
        if self.state in [State.GENERICFAILED, State.GENERICREJECT]:
            self.state = State(data[0:2])
        if self.state is State.BUSY:
            self.busy_time = data[1] * 0.1
        logging.info(f'Device state: {self.state.name}')
        self._execute(Command.ACK)

    @threaded
    def _wait_states(self, states: list[State]) -> None:
        while True:
            self.poll()
            if self.state in states:
                return
            time.sleep(0.1)

    def _execute(self, command: Command, data: bytes = b'') -> bytes:
        logging.info(f'Command: {command.name}')

        byte_cmd = command.value()
        package_len = len(byte_cmd) + len(data) + 5
        if package_len < 250:
            payload = b''.join((package_len.to_bytes(1, 'little'), byte_cmd, data))
        elif package_len < 1 << 16:
            payload = b''.join((b'\x00', byte_cmd, (package_len + 1).to_bytes(2, 'little')))
        else:
            raise ValueError('Payload size exceeds 2 bytes, length: ', package_len)
        try:
            package = b''.join([self.sync, self.device_type, payload])
            package += self._crc16(package)  # Add checksum to the end
            logging.debug('Send: ', package)
            self.connection.write(package)
        except serial.SerialTimeoutException as e:
            logging.error("Timeout: ", e)
        except Exception as e:
            raise e
        try:
            response = self.connection.read(3)
            to_read = response[2] - 3  # Byte 3 contains msg length or 0 if msg is too big
            if to_read == -3:  # Otherwise bytes 4 and 5 contribute to msg length
                response += self.connection.read(2)
                to_read = ((response[3] << 8) | response[4]) - 5
            data = self.connection.read(to_read - 2)  # read data block
            response += data  # append data to full response msg
            response += self.connection.read(2)  # read crc block
            logging.debug('Received: ', response)
            self._check_response(response)

            return data
        except serial.SerialTimeoutException:
            logging.error('Device timeout')
        except Exception as e:
            raise e

    @staticmethod
    def _crc16(data: bytes) -> bytes:
        crc = 0
        for byte in data:
            crc ^= byte
            for j in range(0, 8):
                if crc & 0x0001:
                    crc >>= 1
                    crc ^= 0x8408
                else:
                    crc >>= 1
        return crc.to_bytes(2, 'little')

    def _check_response(self, rsp: bytes) -> bytes:
        if rsp[0] != self.sync or rsp[1] != self.device_type:
            raise Exception('Wrong response target' + rsp[0:1].hex() + rsp[1:2].hex())

        msg, crc_rcv = rsp[0:-2], rsp[-2:]
        crc_calc = self._crc16(msg)

        if crc_rcv != crc_calc:
            raise Exception(f'Error, correction codes do not match. Calculated: {crc_calc}')

        return rsp
