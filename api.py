from fastapi import FastAPI, HTTPException
import multiprocessing
import time
import os
import sys

# Añadiendo el path para asegurar las importaciones
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'features_capture_mp')))

from features_capture_mp.settings.config import NETWORK_INTERFACE, PCAP_FILE
from features_capture_mp.capture import Capture
from features_capture_mp.settings import logger as logging
from features_capture_mp.utils import verify_interface

app = FastAPI()

def run_capture():
    interface = NETWORK_INTERFACE
    out_file = PCAP_FILE
    if verify_interface(interface):
        capture = Capture(interface, out_file)
        capture.start()
    else:
        logging.error(f'Interface {interface} doesnt exists, exiting application')
        sys.exit()

@app.post("/start-capture")
def start_capture():
    try:
        process = multiprocessing.Process(target=run_capture)
        process.start()
        return {"status": "Capture started", "pid": process.pid}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/status")
def status():
    return {"status": "API is running"}