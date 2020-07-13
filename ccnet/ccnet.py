import sys
import logging
import site
logging.error(site)
logging.error(sys.path)

logging.basicConfig(level=logging.DEBUG)

import threading
import serial
import struct
import binascii
from functools import wraps
import errno
import os
import signal
import math
import struct
import traceback


def return_buffer(data):
    def func():
        return data
    return func


def data_proxy(data):
    return data


def check_error(data):
    if not data:
        return "No response"

    data = struct.unpack('b', data)
    if data[0] == 0:
        return "Done"
    elif data[0] == 255:
        return "Error"
    else:
        return "Unknown response"


def get_status_response(data):
    return {
        'enabledBills': bytes.fromhex(data[0:3]),
        'highSecurity': bytes.fromhex(data[3:6]),
    }


def enable_bill_types_request(data):
    return '34'+''.join(["%02X" % x for x in data]).strip()
    # bytearray.fromhexdata.decode('hex')


def identification_response(data):
    return {
        'Part': str(data[0:15]).strip(),
        'Serial': str(data[15:27]).strip(),
        'Asset': data[27:34],
    }


def get_bill_table_response(data):
    data = bytearray(data)
    response = []
    for i in range(0, 23):
        word = data[i*5:i*5+5]
        cur_nom = word[0]
        cur_pow = word[4]
        response.append({
            'amount': cur_nom * math.pow(10, cur_pow),
            'code': str(word[1:4]),
        })
    return response

comamnds_dict = {
    'RESET':                [return_buffer('30'), check_error],
    'GET STATUS':           [return_buffer('31'), get_status_response],
    'SET SECURITY':         [return_buffer('32'), data_proxy],
    'POLL':                 [return_buffer('33'), data_proxy],
    'ENABLE BILL TYPES':    [enable_bill_types_request, check_error],
    'STACK':                [return_buffer('35'), data_proxy],
    'RETURN':               [return_buffer('36'), data_proxy],
    'IDENTIFICATION':       [return_buffer('37'), identification_response],
    'HOLD':                 [return_buffer('38'), data_proxy],
    'SET BARCODE PARAMETERS': [return_buffer('39'), data_proxy],
    'EXTRACT BARCODE DATA': [return_buffer('3A'), data_proxy],
    'GET BILL TABLE':       [return_buffer('41'), get_bill_table_response],
    'DOWNLOAD':             [return_buffer('50'), data_proxy],
    'GET CRC32 OF THE CODE': [return_buffer('51'), data_proxy],
    'REQUEST STATISTICS':   [return_buffer('60'), data_proxy],
    'ACK':   [return_buffer('00'), data_proxy],
}


class req_res(object):
    def __init__(self, command):
        self.request = comamnds_dict[command][0]
        self.response = comamnds_dict[command][1]


class Commands(object):
    def __call__(self, command):
        return req_res(command)


class TimeoutError(Exception):
    pass

#def timeout(seconds=30, error_message=os.strerror(errno.ETIME)):
#    def decorator(func):
#        def _handle_timeout(signum, frame):
#            raise TimeoutError(error_message)

#        def wrapper(*args, **kwargs):
#            result = False
#            signal.signal(signal.SIGALRM, _handle_timeout)
#            signal.alarm(seconds)
#            try:
#                result = func(*args, **kwargs)
#            finally:
#                signal.alarm(0)
#            return result

#        return wraps(func)(wrapper)

#    return decorator

import ctypes


def timeout(seconds=30, error_message=os.strerror(errno.ETIME)):
    def decorator(func):
        def wrapper(*args, **kwargs):

            result = None

            def runner():
                nonlocal result
                result = func(*args, **kwargs)
                return result

            t = threading.Thread(target=runner)
            t.start()
            t.join(seconds)
            if t.is_alive():
                ctypes.pythonapi.PyThreadState_SetAsyncExc(t.ident, ctypes.py_object(TimeoutError))
                raise TimeoutError(error_message)

            return result

        return wrapper
    return decorator



# cmd('POLL').request()
class CCNET(object):
    """CCNET protocol for cashcode serial"""
    states = {
        0x10: 'Power UP',
        0x11: 'Power Up with Bill in Validator',
        0x12: 'Power Up with Bill in Stacker',
        0x13: 'Initialize',
        0x14: 'Idling',
        0x15: 'Accepting',
        0x17: 'Stacking',
        0x18: 'Returning',
        0x19: 'Unit Disabled',
        0x1A: 'Holding',
        0x1B: 'Device Busy',
        0x1C: 'Rejecting',
        0x41: 'Drop Cassette Full',
        0x42: 'Drop Cassette out of position',
        0x43: 'Validator Jammed',
        0x44: 'Drop Cassette Jammed',
        0x45: 'Cheated',
        0x46: 'Pause',
        0x47: 'Failed',
        0x80: 'Escrow position',
        0x81: 'Bill stacked',
        0x82: 'Bill returned'}
    busy = False
    billTable = []
    sync = '02'
    state = 0x10
    device = {'Part': None, 'Serial': None, 'Asset': None}

    def __init__(self, port, deviceType="03"):
        self.cmd = Commands()
        self.deviceType = deviceType
        self.connection = serial.Serial(
            port=port, baudrate=9600, timeout=None,
            bytesize=serial.EIGHTBITS, parity=serial.PARITY_NONE)

    def connect(self, cb=False):
        self.connection.close()
        self.connection.open()
        try:
            if self.execute('RESET') == "Done":
                while self.execute('POLL')[0] != 0x19:
                    threading.Event().wait(0.1)
                self.identification()
            else:
                raise Exception('Reset Error')
        except Exception as e:
            traceback.print_exc()
            logging.error("Connection: " + str(e))
            return False
        return True

    def start(self,  billsEnable=(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)):
        self.billTable = self.execute('GET BILL TABLE')
        self.execute('ENABLE BILL TYPES', billsEnable)
        return True

    def identification(self):
        self.device = self.execute('IDENTIFICATION')
        return self.device

    def escrow(self):
        try:
            data = self.wait_state(0x80, dt=True)
            if data:
                return self.billTable[data]
        except TimeoutError as e:
            logging.error('ERR Escrow ' + str(e))
            return False
        except Exception as e:
            logging.error('ERR Escrow ' + str(e))
            raise e

    def stack(self):
        logging.debug("Start stacking")
        ret = self.execute('STACK')
        res = self.wait_state(0x81)
        self.execute('ACK')
        return res

    def retrieve(self):
        logging.debug("Start returning")
        ret = self.execute('RETURN')
        return self.wait_state(0x82)

    def getState(self, h=False, dt=False):
        state = self.state
        try:
            resp = self.execute('POLL') or ''
            self.execute('ACK')
            self.state = resp[0]
        except:
            pass
        if state is not self.state:
            logging.debug("New State:" + str(self.states[self.state]))
        if dt:
            return resp[1] if len(resp) > 1 else None
        elif h:
            return self.states[self.state]
        return self.state

    @timeout(30)
    def wait_state(self, state=0x14, dt=False):
        logging.debug("Wait for state:" + str(self.states[state]))
        if dt:
            dt = self.getState(dt=True)  # Update self.state and get data
            if self.state == state:
                return dt
        else:
            if self.getState() == state:
                return True
        threading.Event().wait(0.1)

    def end(self, billsEnable=(0x00, 0x00, 0x00, 0x00, 0x00, 0xff)):
        self.execute('ENABLE BILL TYPES', billsEnable)

    @timeout(10)
    def execute(self, command, data=None):
        logging.error(command)
        if command != "POLL":  # No pool debug, because Inf/0.1s loop
            logging.debug("Execute: " + str(command) + "[" + str(data) + "]")
        if (self.busy):
            return
        no_response = (command == "ACK")
        if data is None:
            r = self.__send_command(
                self.cmd(command).request(), no_response=no_response)
        else:
            r = self.__send_command(
                self.cmd(command).request(data), no_response=no_response)
        return self.cmd(command).response(r)

    @timeout(30)
    def __send_command(self, command, no_response=False):
        logging.error(command)
        self.busy = True
        try:
            cmmd = ''.join([
                self.sync, self.deviceType, self.getLenght(command), command])
            logging.error(cmmd)
            logging.error(self.getCRC16(cmmd))
            self.connection.write(bytes.fromhex(cmmd + self.getCRC16(cmmd)))
        except serial.SerialTimeoutException:
            logging.error("timeout")
        except Exception as e:
                raise e
        if no_response:
            self.busy = False
            return
        try:
            response = self.connection.read(3)
            response += self.connection.read(
                response[2] - 3)
            self.busy = False
            return self.checkResponse(response)
        except Exception as e:
            raise e

        self.busy = False
        return None

    @staticmethod
    def getCRC16(data, is_hex=True):
        if is_hex:
            data = bytearray.fromhex(data)
        else:
            data = bytearray(data)

        CRC = 0
        for byte in data:
            CRC ^= byte
            for j in range(0, 8):
                if (CRC & 0x0001):
                    CRC >>= 1
                    CRC ^= 0x8408
                else:
                    CRC >>= 1
        logging.error(CRC)
        return CRC.to_bytes(2,'little').hex()

    @staticmethod
    def getLenght(cmd):
        ret = "%X" % (len(cmd)//2 + 5)
        if len(ret) < 2:
            ret = '0' + ret
        return ret

    def checkResponse(self, rsp):
        resp = bytearray(rsp)
        if resp[0] != int(self.sync) or resp[1] != int(self.deviceType):
            raise Exception(
                "Wrong response target" +
                rsp[0].hex() +
                rsp[1].hex())

        CRC = binascii.hexlify(resp[-2:])
        command = resp[0:-2]
        data = resp[3:-2]
        # if(CRC != self.getCRC16(command, False)):
        #     raise Exception("Wrong response command hash" + CRC
        #     "////" + self.getCRC16(command, False)
        #     "////" + binascii.hexlify(command))
        return data

logging.error('loaded')
