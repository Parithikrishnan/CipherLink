# Cipher Link - Secure file transfer via LAN

import subprocess as sp
import platform as p 
import socket as s
import time as t
from tkinter import Tk, Text, Label, Frame, Toplevel, Button, END,Entry, WORD 
from tkinter import simpledialog, filedialog
from PIL import Image, ImageTk, ImageFilter
import os
import hashlib


ip_address = None
System_os = p.system()
#about_text="This application is uses cryptographic and hashing algorithms in order to provide security and privacy over the network.\nThis application uses AVL Tree, Hashing and Multigraph to share Images,Videos,Files,Text over the network in an efficient manner.\n\nThis app was made for Data Structures Laboratory project by Parithikrishnan and Nirupa.\n"


def connection_checking():
    connected_to_wifi = False
    # Wifi network check
    if(System_os == "Linux"):
        wifi_result_linux = sp.run(['nmcli', 'connection' ,'show', '--active'],capture_output=True,text=True)
        if("wifi" in wifi_result_linux.stdout):
            print("Connected to a wifi network\n")
            connected_to_wifi = True
        else:
            print("\nConnect to a wifi network\n")
    elif (System_os == "Windows"):
        wifi_result_windows = sp.run('netsh wlan show interfaces | findstr /R "^ *SSID"',capture_output=True,text=True,)
        if("SSID" not in wifi_result_windows.stdout):
            print("\nConnect to a wifi network\n")
        else:
            connected_to_wifi = True
            print("Connected to a wifi network\n")
    else:
        pass
    # Ip address check
    try:
        a = s.socket(s.AF_INET, s.SOCK_DGRAM)
        a.connect(("8.8.8.8", 80)) 
        local_ip = a.getsockname()[0]
        a.close()
        ip_address = local_ip
    except Exception as e:
        return f"Error getting IP: {e}"
    # Two checks 
    if(connected_to_wifi is True and ip_address is not None):
        return True,ip_address
    else:
        t.sleep(5)
        connection_checking()


checking,ip_address = connection_checking()

    

HOST = '0.0.0.0' 
server_socket = s.socket(s.AF_INET, s.SOCK_STREAM)





root=Tk()
screen_width=root.winfo_screenwidth()
screen_height=root.winfo_screenheight()
window_width=int(screen_width*0.75)
window_height=int(screen_height*0.75)
root.geometry(f"{window_width}x{window_height}+{screen_width//8}+{screen_height//8}")
root.title("Cipher Link - Secure file transfer via LAN")
username=None
while not username:
    username=simpledialog.askstring("Username","Please enter your username:")
bg_image_path="futuristic.png"
bg_image=Image.open(bg_image_path).resize((window_width,window_height),Image.LANCZOS)
bg_photo=ImageTk.PhotoImage(bg_image)
bg_label=Label(root,image=bg_photo)
bg_label.place(relwidth=1,relheight=1)
label_width,label_height=500,80
label_x=int((window_width-label_width)/2)
label_y=int(window_height*0.08)
blurred_label=bg_image.crop((label_x,label_y,label_x+label_width,label_y+label_height)).filter(ImageFilter.GaussianBlur(radius=8))
label_photo=ImageTk.PhotoImage(blurred_label)
blur_label=Label(root,image=label_photo,bd=0)
blur_label.image=label_photo
blur_label.place(x=label_x,y=label_y,width=label_width,height=label_height)
welcome_label=Label(root,text=f"Hello, {username}!\nIP:{ip_address}",font=("Arial",36,"bold"),fg="white",bg="black")
welcome_label.place(x=label_x+(label_width//2),y=label_y+(label_height//2),anchor="center")
frame_width,frame_height=420,520
frame_x=int((window_width-frame_width)/2)
frame_y=int(window_height*0.3)
blurred_frame=bg_image.crop((frame_x,frame_y,frame_x+frame_width,frame_y+frame_height)).filter(ImageFilter.GaussianBlur(radius=8))
frame_photo=ImageTk.PhotoImage(blurred_frame)
blur_frame=Label(root,image=frame_photo,bd=0)
blur_frame.image=frame_photo
blur_frame.place(x=frame_x,y=frame_y,width=frame_width,height=frame_height)
button_frame=Frame(root,bg="black",highlightthickness=0)
button_frame.place(x=frame_x,y=frame_y,width=frame_width,height=frame_height)
output_window=None
output_text=None

def display_output(text):
    global output_text
    if output_text:
        output_text.insert(END, text + "\n")
        output_text.see(END)

def chat_backend():
    pass

def send_file_backend():
    global server_socket
    server_socket = s.socket(s.AF_INET, s.SOCK_STREAM)
    t.sleep(1)
    display_output(f"Scanning for people on the network\nThe IP address of the server is {ip_address}\n")
    try:
        server_socket.bind((HOST, 52837))
    except:
        server_socket.bind((HOST, 52838))
    server_socket.listen(1)
    conn, addr = server_socket.accept()
    display_output(f"Connection established with {addr}")
    conn.send(username.encode('utf-8'))
    username_of_receiver = conn.recv(1024).decode('utf-8')
    display_output(f"The name of the receiver is {username_of_receiver}\n")
    file_path = filedialog.askopenfilename(title="Select file to send")
    if not file_path:
        display_output("No file selected. Exiting.")
        conn.close()
        server_socket.close()
        return
    file_name = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)
    hash_object = hashlib.sha256(username.encode())
    hash_hex = hash_object.hexdigest()
    conn.send(hash_hex.encode('utf-8'))
    display_output("Hash of the username is sent\n")
    h = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    file_hashing = h.hexdigest()
    conn.send(file_hashing.encode('utf-8'))
    display_output("Hash of the file is sent\n")
    metadata = file_name+'|'+str(file_size)
    conn.send(metadata.encode('utf-8'))
    t.sleep(2)
    with open(file_path, 'rb') as f:
        while chunk := f.read(1024):
            conn.send(chunk)
    display_output("File sent successfully.")

    conn.close()
    server_socket.close()

def receive_file_backend():
    try:
        client_socket = s.socket(s.AF_INET, s.SOCK_STREAM)
        while True:
            SERVER_IP = simpledialog.askstring("Server IP", "Enter the IP address of the server:")
            if SERVER_IP is None:
                return
            try:
                parts = SERVER_IP.split('.')
                if len(parts) != 4:
                    raise ValueError
            except:
                display_output("The format is wrong. Please enter it again (e.g., 192.168.0.1)\n")
                continue
            try:
                try:
                    if(System_os == "Linux"):
                        pinger = sp.run(['ping','-w','10','-c','1',SERVER_IP],text=True,capture_output=True)
                    else:
                        pinger= sp.run(["ping", "-n", "1", "-w", "1000", SERVER_IP,],text=True,capture_output=True)
                    if('64 bytes from' in pinger.stdout):
                        client_socket.connect((SERVER_IP, 52837))
                        break
                    elif('Destination Host Unreachable' in pinger):
                        continue
                    else:
                        continue
                except:
                    pinger = sp.run(['ping',SERVER_IP,'p','52838'],text=True,capture_output=True,timeout=10)
                    if('64 bytes from' in pinger.stdout):
                        client_socket.connect((SERVER_IP, 52838))
                        break
                    elif('Destination Host Unreachable' in pinger):
                        continue
                    else:
                        continue
            except:
                display_output("The IP address you have entered is wrong\n")
                continue
        display_output("Connected to the server.")
        username_of_sender = client_socket.recv(1024).decode('utf-8')
        client_socket.send(username.encode("utf-8"))
        display_output(f"The name of the sender is {username_of_sender}")
        hash_object = hashlib.sha256(username_of_sender.encode())
        expected_username_hash = hash_object.hexdigest()

        received_username_hash = client_socket.recv(64).decode('utf-8')  
        if received_username_hash != expected_username_hash:
            display_output("The hashing is not being verified\nPlease try again\n")
            client_socket.close()
            return
        display_output("Hash of the username is verified\n")
        file_integrity = client_socket.recv(64).decode('utf-8')
        display_output("Received file integrity hash.")
        metadata = client_socket.recv(1024).decode('utf-8')
        file_name, file_size = metadata.split("|")
        file_size = int(file_size)
        display_output(f"Receiving file: {file_name} ({file_size} bytes)")
        file_path = f"Saver/received_{file_name}"
        bytes_received = 0
        with open(file_path, "wb") as f:
            while bytes_received < file_size:
                chunk_size = min(4096, file_size - bytes_received)
                chunk = client_socket.recv(chunk_size)
                if not chunk:
                    break
                f.write(chunk)
                bytes_received += len(chunk)
        display_output(f"File saved as: {file_path}")
        h = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        calculated_hash = h.hexdigest()

        if calculated_hash == file_integrity:
            display_output("The file is verified and transferred in a safe manner\n")
        else:
            display_output("The file is not transferred safely\nBe cautious in using the file\n")

        client_socket.close()
    except Exception as e:
        display_output(f"Error: {e}")


def about_backend():
    return '''Cipher Link v1.0
Secure file transfer and chat over LAN.
Features:
- Encrypted messaging
- Fast and secure file transfers
- Easy-to-use interface
'''

def open_new_page(title,backend_func=None):
    global output_window,output_text
    output_window=Toplevel(root)
    output_window.geometry(f"{window_width}x{window_height}+{screen_width//8}+{screen_height//8}")
    output_window.title(title)
    new_bg=Image.open(bg_image_path).resize((window_width,window_height),Image.LANCZOS)
    new_bg_photo=ImageTk.PhotoImage(new_bg)
    new_bg_label=Label(output_window,image=new_bg_photo)
    new_bg_label.image=new_bg_photo
    new_bg_label.place(relwidth=1,relheight=1)
    code_frame=Frame(output_window,bg="#0a1a2a",bd=2,highlightbackground="#00b4d8")
    code_frame.place(relwidth=0.9,relheight=0.8,relx=0.05,rely=0.1)
    output_text=Text(code_frame,font=("Courier",12),fg="white",bg="#0a1a2a",insertbackground="white",wrap="word")
    output_text.pack(fill="both",expand=True,padx=10,pady=10)
    if backend_func and title != "About App":
        def delayed_backend():
            output_window.after(200, backend_func)
        output_window.after(50, delayed_backend)
    elif backend_func:
        output_text.insert("1.0",backend_func())
    back_button=Button(output_window,text="Back",command=output_window.destroy,
                       font=("Arial",12,"bold"),fg="white",bg="#1a2a3a",
                       activebackground="#00b4d8",activeforeground="black",
                       relief="flat",padx=10,pady=5)
    back_button.place(relx=0.9,rely=0.03)

def on_enter(e):e.widget.config(bg="#0a1a2a",fg="cyan",relief="raised")
def on_leave(e):e.widget.config(bg="black",fg="white",relief="flat")
def styled_button(text,backend_func=None):
    btn=Button(button_frame,text=text,command=lambda:open_new_page(text,backend_func),
               font=("Arial",26,"bold"),fg="white",bg="black",
               activebackground="#0096c7",activeforeground="black",
               relief="flat",padx=30,pady=15,borderwidth=0,highlightthickness=0)
    btn.pack(pady=20)
    btn.bind("<Enter>",on_enter)
    btn.bind("<Leave>",on_leave)
styled_button("Chat",chat_backend)
styled_button("Send File",send_file_backend)
styled_button("Receive File",receive_file_backend)
styled_button("About App",about_backend)
root.mainloop()

