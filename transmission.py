import pyaudio
import wave

FORMAT = pyaudio.paInt16
CHUNK = 1024
CHANNELS = 1
SAMPLE_RATE = 44100

def write_file(data, filename):
    p = pyaudio.PyAudio()
    wave_file = wave.open(filename, 'wb')
    wave_file.setnchannels(CHANNELS)
    wave_file.setsampwidth(p.get_sample_size(FORMAT))
    wave_file.setframerate(SAMPLE_RATE)
    wave_file.writeframes(data)
    wave_file.close()

