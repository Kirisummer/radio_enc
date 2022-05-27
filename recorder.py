import audioconf

def record_sound(seconds):
    stream = audioconf.PYAUDIO.open(format=audioconf.FORMAT,
                                    channels=audioconf.CHANNELS,
                                    rate=audioconf.SAMPLE_RATE,
                                    input=True,
                                    output=False,
                                    frames_per_buffer=audioconf.CHUNK)
    frames = []
    print('Recording start')
    record_loops = audioconf.SAMPLE_RATE * seconds // audioconf.CHUNK
    for i in range(record_loops):
        data = stream.read(audioconf.CHUNK)
        frames.append(data)
    print('Recording end')
    stream.stop_stream()
    stream.close()
    return b''.join(frames)

