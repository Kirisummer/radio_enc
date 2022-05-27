import audioconf
import wave

def write_file(data, filename):
    wave_file = wave.open(filename, 'wb')
    wave_file.setnchannels(audioconf.CHANNELS)
    wave_file.setsampwidth(audioconf.PYAUDIO.get_sample_size(audioconf.FORMAT))
    wave_file.setframerate(audioconf.SAMPLE_RATE)
    wave_file.writeframes(data)
    wave_file.close()

