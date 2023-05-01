import logging
import time

import serial

from config import baudrate, serial_timeout
from .structs import State, Command, accepted_bills, threaded, Device, Bill


class CCNET(object):
    """CCNET protocol controller for CashCode Bill Validator"""

    busy_time = .0
    bill_table: dict[int, Bill] = {}
    sync = b'\x02'
    device_type = b'\x03'
    state = State.POWERUP
    cur_bill: Bill | None = None
    device = Device('', '', b'')

    def __init__(self, port):
        self._serial = serial.Serial(baudrate=baudrate, timeout=serial_timeout)
        self._serial.port = port

    def connect(self):
        self._serial.close()
        self._serial.open()

        # self.poll()
        self.reset()
        self.identification()
        self.get_bill_table()

    def disconnect(self):
        self._execute(Command.RESET)
        self._serial.close()

    def reset(self):
        self._execute(Command.RESET)
        self._wait_states(5, [State.DISABLED])

    def get_status(self) -> bytes:
        logging.info('Get device status')
        data = self._execute(Command.GETSTATUS)
        self._execute(Command.ACK)
        return data

    def enable_bills(self, bills_enabled=accepted_bills, escrow_bills=tuple(range(24))) -> bool:
        data = 0

        for collection in [bills_enabled, escrow_bills]:
            data <<= 24
            part = 0
            for bill_bit_number in collection:
                mask = 1
                mask <<= bill_bit_number
                part |= mask
            part &= (1 << 24) - 1  # Check part is less than 24 bits (3 bytes)
            data |= part

        rsp = self._execute(Command.ENABLEBILLS, data.to_bytes(6, 'little'))
        if Command(rsp[0:1]) is not Command.ACK:
            logging.error('Got bad response for ENABLE BILLS command: ', rsp)
            self.reset()
            return False
        self._wait_states(5, [State.IDLING])
        return True

    def check_accepted_bills(self) -> bool:
        for bit, bill in accepted_bills.items():
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

    def stack_bill(self) -> Bill | None:
        logging.debug('Stack bill')
        return self._move_bill(Command.STACK, State.BILLSTACKED)

    def return_bill(self) -> Bill | None:
        logging.info('Return bill')
        return self._move_bill(Command.RETURN, State.BILLRETURNED)

    def _move_bill(self, command: Command, state: State) -> Bill | None:
        if self.state is State.ACCEPTING:
            self._wait_states(timeout=5, state=[State.ESCROWPOSITION])
        if self.state not in [State.ESCROWPOSITION, State.HOLDING]:
            logging.error('Device not in ESCROW or HOLDING state')
            return
        data = self._execute(command)
        if Command(data[0:1]) is not Command.ACK:
            logging.error(f'Got bad response for {command.name} command: ', data)
            return
        self._wait_states(timeout=30, states=[state])
        if self.state is not state:
            logging.error(f'Have not got {state.name} state')
            return
        self.poll()
        return self.bill_table[data[1]]

    def poll(self) -> None:
        data = self._execute(Command.POLL)
        self.state = State(data[0:1])
        if self.state in [State.GENERICFAILED, State.GENERICREJECT]:
            self.state = State(data[0:2])
        elif self.state is State.BUSY:
            self.busy_time = data[1] * 0.1
        elif self.state in [State.ESCROWPOSITION, State.BILLRETURNED, State.BILLSTACKED]:
            self.cur_bill = self.bill_table[data[1]]

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

        byte_cmd = command.value
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
            self._serial.write(package)
        except serial.SerialTimeoutException as e:
            logging.error("Timeout: ", e)
        except Exception as e:
            raise e
        if command in [Command.ACK, Command.NAK]:
            return b''
        try:
            response = self._serial.read(3)
            to_read = response[2] - 3  # Byte 3 contains msg length or 0 if msg is too big
            if to_read == -3:  # Otherwise bytes 4 and 5 contribute to msg length
                response += self._serial.read(2)
                to_read = ((response[3] << 8) | response[4]) - 5
            data = self._serial.read(to_read - 2)  # read data block
            response += data  # append data to full response msg
            response += self._serial.read(2)  # read crc block
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
        if rsp[0:1] != self.sync or rsp[1:2] != self.device_type:
            raise Exception('Wrong response target: ' + rsp[0:1].hex() + rsp[1:2].hex())

        msg, crc_rcv = rsp[0:-2], rsp[-2:]
        crc_calc = self._crc16(msg)

        if crc_rcv != crc_calc:
            raise Exception(f'Error, correction codes do not match. Calculated: {crc_calc}')

        return rsp
