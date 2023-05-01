import ctypes
import threading
from dataclasses import dataclass
from enum import Enum


def threaded(func):
    def wrapper(self, timeout=10, *args, **kwargs) -> None | bytes:
        result = None

        def runner():
            nonlocal result
            result = func(self, *args, **kwargs)
            return result

        t = threading.Thread(target=runner)
        t.start()
        t.join(timeout)
        if t.is_alive():
            ctypes.pythonapi.PyThreadState_SetAsyncExc(t.ident, ctypes.py_object(TimeoutError))
            raise TimeoutError('Timed out')

        return result

    return wrapper


@dataclass
class Bill:
    amount: int
    code: str


accepted_bills = {  # bill bit number: Bill
    2: Bill(10, 'RUS'),
    3: Bill(50, 'RUS'),
    4: Bill(100, 'RUS'),
    5: Bill(500, 'RUS'),
    6: Bill(1000, 'RUS'),
    7: Bill(5000, 'RUS')
}


@dataclass
class Device:
    part: str
    serial: str
    asset: bytes


class State(Enum):
    """Bill Validator states"""
    POWERUP = b'\x10'
    POWERUPVALIDATOR = b'\x11'
    POWERUPSTACKER = b'\x12'
    INITIALIZE = b'\x13'
    IDLING = b'\x14'
    ACCEPTING = b'\x15'
    STACKING = b'\x17'
    RETURNING = b'\x18'
    DISABLED = b'\x19'
    HOLDING = b'\x1A'
    BUSY = b'\x1B'

    GENERICREJECT = b'\x1C'
    INSERTION = b'\x1C\x60'
    MAGNETIC = b'\x1C\x61'
    REMAINEDBILL = b'\x1C\x62'
    MULTIPLYING = b'\x1C\x63'
    CONVEYING = b'\x1C\x64'
    IDENTIFICATION = b'\x1C\x65'
    VERIFICTION = b'\x1C\x66'
    OPTIC = b'\x1C\x67'
    INHIBIT = b'\x1C\x68'
    CAPACITY = b'\x1C\x69'
    OPERATION = b'\x1C\x6A'
    LENGTH = b'\x1C\x6C'
    UV = b'\x1C\x6D'
    UNKNOWNBARCODE = b'\x1C\x92'
    INCONSISTENTBARCODE = b'\x1C\x93'
    BARCODESTART = b'\x1C\x94'
    BARCODESTOP = b'\x1C\x95'

    CASSETTEFULL = b'\x41'
    CASSETTEOUT = b'\x42'
    VALIDATORJAMMED = b'\x43'
    CASSETTEJAMMED = b'\x44'
    CHEATED = b'\x45'
    PAUSE = b'\x46'

    GENERICFAILED = b'\x47'
    DROPCASSETTEMOTOR = b'\x47\x50'
    TRANSPORTMOTORSPEED = b'\x47\x51'
    TRANSPORTMOTOR = b'\x47\x52'
    ALIGNINGMOTOR = b'\x47\x53'
    INITIALCASSETTE = b'\x47\x54'
    OPTICCANAL = b'\x47\x55'
    MAGNETICCANAL = b'\x47\x56'
    CAPACITANCECANAL = b'\x47\x5F'

    ESCROWPOSITION = b'\x80'
    BILLSTACKED = b'\x81'
    BILLRETURNED = b'\x82'


class Command(Enum):
    RESET = b'\x30'
    GETSTATUS = b'\x31'
    SETSECURITY = b'\x32'
    POLL = b'\x33'
    ENABLEBILLS = b'\x34'
    STACK = b'\x35'
    RETURN = b'\x36'
    IDENTIFICATION = b'\x37'
    HOLD = b'\x38'
    SETBARCODEPARAM = b'\x39'
    EXTRACTBARCODEDATA = b'\x3A'
    BILLTABLE = b'\x41'
    DOWNLOAD = b'\x50'
    CRC32 = b'\x51'
    STATISTICS = b'\x60'
    ACK = b'\x00'
    NAK = b'\xFF'
