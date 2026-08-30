from tkinter import Label
import tkinter as tk

window = tk.Tk()
window.title("Network System")
window.geometry("800x600")

label = Label(window, text="Network System")
label.pack(pady=20)

def say_hello():
    label.config(text="Hello World")

button = tk.Button(window, text="Say Hello", command=say_hello)
button.pack(pady=20)

window.mainloop()