import pyaudio

FORMAT = pyaudio.paInt16
CHUNK = 1024
CHANNELS = 1
SAMPLE_RATE = 44100
PYAUDIO = None

def init():
    global PYAUDIO
    PYAUDIO = pyaudio.PyAudio()

def terminate():
    global PYAUDIO
    PYAUDIO.terminate()

