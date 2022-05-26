import pyaudio

FORMAT = pyaudio.paInt16
CHUNK = 1024
CHANNELS = 1
SAMPLE_RATE = 44100

def record_sound(seconds):
    p = pyaudio.PyAudio()
    stream = p.open(format=FORMAT,
                    channels=CHANNELS,
                    rate=SAMPLE_RATE,
                    input=True,
                    output=False,
                    frames_per_buffer=CHUNK)
    frames = []
    print('Recording start')
    for i in range(int(SAMPLE_RATE / CHUNK * seconds)):
        data = stream.read(CHUNK)
        frames.append(data)
    print('Recording end')
    stream.stop_stream()
    stream.close()
    p.terminate()
    return b''.join(frames)

