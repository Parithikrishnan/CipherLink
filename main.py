# Cipher Link - Secure file transfer via LAN

import subprocess as sp
import platform as p 
import socket as s
import time as t
from tkinter import Tk, Text, Label, Frame, Toplevel, Button, END,Entry, WORD,DISABLED,LEFT, RIGHT,X,Y
from tkinter import simpledialog, filedialog, messagebox,Scrollbar,BOTH
from PIL import Image, ImageTk, ImageFilter
import os
import hashlib
import threading as th
from collections import defaultdict


#----------------------------------------------------------------------------------------------------------------------------------


ip_address = None
System_os = p.system()


#-----------------------------------------------------------------------------------------------------------------------------------



def connection_checking():
    connected_to_wifi = False
    # Wifi network check
    if(System_os == "Linux"):
        wifi_result_linux = sp.run(['nmcli', 'connection' ,'show', '--active'],capture_output=True,text=True)
        if("wifi" in wifi_result_linux.stdout):
            connected_to_wifi = True
        else:
            connected_to_wifi = False
    elif (System_os == "Windows"):
        wifi_result_windows = sp.run('netsh wlan show interfaces | findstr /R "^ *SSID"',capture_output=True,text=True,)
        if("SSID" not in wifi_result_windows.stdout):
            connected_to_wifi = False
        else:
            connected_to_wifi = True
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


#------------------------------------------------------------------------------------------------------------------------------

checking,ip_address = connection_checking()
HOST = '0.0.0.0' 
server_socket = s.socket(s.AF_INET, s.SOCK_STREAM)


#---------------------------------------------------------------------------------------------------------------------------------


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

#----------------------------------------------------------------------------------------------------------------------------------


def display_output(text):
    global output_text
    if output_text:
        output_text.insert(END, text + "\n")
        output_text.see(END)


#----------------------------------------------------------------------------------------------------------------------------------

def chat_backend():

    global connected_socket
    connected_socket = None  


    class MultiGraph:
        def __init__(self):
            self.graph = defaultdict(list) 

        def add_edge(self, sender, receiver, message):
            timestamp = int(t.time())
            self.graph[sender].append((receiver, message, timestamp))

        def get_messages(self, user1, user2):
            return [(r, m, t) for r, m, t in self.graph[user1] if r == user2]

        def display_all(self):
            for sender in self.graph:
                print(f"{sender} sent messages to:")
                for receiver, message, timestamp in self.graph[sender]:
                    print(f"  ➤ {receiver}: {message} [{timestamp}]")

        def save_to_text(self, filename="chat_logs.txt"):
            with open(filename, "w", encoding="utf-8") as f:
                for sender in self.graph:
                    for receiver, message, timestamp in self.graph[sender]:
                        escaped_message = message.replace('"', '\\"')
                        f.write(f'multigraph.add_edge("{sender}", "{receiver}", "{escaped_message}", {timestamp})\n')



    class AVLTreeNode:
        def __init__(self, key, message):
            self.key = key
            self.message = message
            self.left = None
            self.right = None
            self.height = 1

    class AVLTree:
        def __init__(self):
            self.root = None

        def get_height(self, node):
            return node.height if node else 0

        def get_balance(self, node):
            return self.get_height(node.left) - self.get_height(node.right)

        def rotate_right(self, y):
            x = y.left
            T2 = x.right
            x.right = y
            y.left = T2
            y.height = max(self.get_height(y.left), self.get_height(y.right)) + 1
            x.height = max(self.get_height(x.left), self.get_height(x.right)) + 1
            return x

        def rotate_left(self, x):
            y = x.right
            T2 = y.left
            y.left = x
            x.right = T2
            x.height = max(self.get_height(x.left), self.get_height(x.right)) + 1
            y.height = max(self.get_height(y.left), self.get_height(y.right)) + 1
            return y

        def insert(self, root, key, message):
            if not root:
                return AVLTreeNode(key, message)
            if key < root.key:
                root.left = self.insert(root.left, key, message)
            else:
                root.right = self.insert(root.right, key, message)

            root.height = max(self.get_height(root.left), self.get_height(root.right)) + 1
            balance = self.get_balance(root)

            if balance > 1 and key < root.left.key:
                return self.rotate_right(root)
            if balance < -1 and key > root.right.key:
                return self.rotate_left(root)
            if balance > 1 and key > root.left.key:
                root.left = self.rotate_left(root.left)
                return self.rotate_right(root)
            if balance < -1 and key < root.right.key:
                root.right = self.rotate_right(root.right)
                return self.rotate_left(root)
            return root

        def add_message(self, key, message):
            self.root = self.insert(self.root, key, message)
            with open("chat_tree.txt", "w", encoding="utf-8") as f:
                self.save_tree_structure(self.root, f)

        def save_tree_structure(self, node, f, level=0, prefix="Root: "):
            if node is not None:
                self.save_tree_structure(node.right, f, level + 1, "R---- ")
                f.write("     " * level + prefix + f"[{node.key}] {node.message}\n")
                self.save_tree_structure(node.left, f, level + 1, "L---- ")

    def display_output(text):
        global output_text
        if output_text:
            output_text.insert(END, text + "\n")
            output_text.see(END)

    def create_gui():
        global output_window, output_text, message_entry, send_button, server_button, client_button

        chat_frame = Frame(output_window, bg="#0a1a2a", bd=2, highlightbackground="#00b4d8")
        chat_frame.place(relwidth=0.9, relheight=0.75, relx=0.05, rely=0.05)

        output_text = Text(chat_frame, font=("Courier", 12), fg="white", bg="#0a1a2a",
                           insertbackground="white", wrap="word")
        output_text.pack(fill="both", expand=True, padx=10, pady=10)

        input_frame = Frame(output_window, bg="#001f3f")
        input_frame.place(relwidth=0.9, relheight=0.1, relx=0.05, rely=0.82)

        message_entry = Entry(input_frame, font=("Arial", 12), fg="black")
        message_entry.pack(side="left", fill="x", expand=True, padx=(10, 5), pady=10)

        send_button = Button(input_frame, text="Send", font=("Arial", 12, "bold"),
                             bg="#00b4d8", fg="white", padx=15, pady=5)
        send_button.pack(side="right", padx=(5, 10))

        action_frame = Frame(output_window, bg="#001f3f")
        action_frame.place(relwidth=0.9, relheight=0.07, relx=0.05, rely=0.93)

        server_button = Button(action_frame, text="Start Server", font=("Arial", 11, "bold"),
                               bg="#28a745", fg="white", padx=10, pady=5)
        server_button.pack(side="left", padx=20)

        client_button = Button(action_frame, text="Join Server", font=("Arial", 11, "bold"),
                               bg="#007bff", fg="white", padx=10, pady=5)
        client_button.pack(side="left", padx=20)

        server_button.config(command=start_server)
        client_button.config(command=join_server)
        send_button.config(command=send_message)

    username_of = ""
    tree = AVLTree()
    multigraph = MultiGraph()


    def start_server():
        global connected_socket, username_of, username
        try:
            server_socket = s.socket(s.AF_INET, s.SOCK_STREAM)
            try:
                server_socket.bind(('0.0.0.0', 5293))
            except:
                server_socket.bind(('0.0.0.0',5298))
            server_socket.listen(1)
            display_output("Server started and listening...\n")
            connected_socket, addr = server_socket.accept()
            display_output(f"{addr} connected\n")
            username_of = connected_socket.recv(1024).decode('utf-8')
            display_output(f"{username_of} joined the server with ip {addr}\n")
            connected_socket.send(username.encode('utf-8'))
            th.Thread(target=handle_receive, args=(connected_socket,), daemon=True).start()
        except Exception as e:
            display_output(f"Server Error: {e}")

    def join_server():
        global connected_socket, username_of, username
        try:
            connected_socket = s.socket(s.AF_INET, s.SOCK_STREAM)
            while True:
                ip = simpledialog.askstring("Enter Server IP", "Server IP:")
                if ip is None:
                    return  
                try:
                    parts = ip.split('.')
                    if len(parts) != 4:
                        raise ValueError
                    else:
                        if ip is not None:
                            one,two,three,four = ip.split('.')
                            one1,two2,three3,four4 = ip_address.split('.')
                            if(one == one1 and two == two2 and three == three3):
                                pass
                            else:
                                display_output("This ip is not in your network\n")
                                continue
                except:
                    display_output("The format is wrong. Please enter it again (e.g., 192.168.0.1)\n")
                    continue
                try:
                    try:
                        connected_socket.connect((ip, 5293))
                        break
                    except:
                        connected_socket.connect((ip,5298))
                        break
                except:
                    display_output("The IP address you have entered is wrong\n")
                    continue
                    
            display_output(f"YOU are connected to the chat server\n")
            connected_socket.send(username.encode('utf-8'))
            username_of = connected_socket.recv(1024).decode('utf-8')
            display_output(f"You are chatting with {username_of}\n")
            th.Thread(target=handle_receive, args=(connected_socket,), daemon=True).start()
        except Exception as e:
            display_output(f"Client Error: {e}")

    def handle_receive(sock):
        global username_of
        while True:
            try:
                msg = sock.recv(1024).decode()
                if msg:
                    timestamp = int(t.time())
                    tree.add_message(timestamp, f"{username_of}: {msg}")
                    multigraph.add_edge(username_of, username, msg)
                    multigraph.save_to_text()
                    output_text.insert("end", f"{username_of}: {msg}\n")
                    output_text.see("end")
            except:
                break

    def send_message():
        global connected_socket, username
        msg = message_entry.get()
        if msg:
            message_entry.delete(0, "end")
            timestamp = int(t.time())
            tree.add_message(timestamp, f"{username}: {msg}")
            output_text.insert("end", f"{username}: {msg}\n")
            multigraph.add_edge(username, username_of, msg)
            multigraph.save_to_text()
            output_text.see("end")
            try:
                if connected_socket:
                    connected_socket.send(msg.encode())
                else:
                    output_text.insert("end", "No active connection.\n")
            except Exception as e:
                output_text.insert("end", f"Failed to send: {e}\n")

    if(checking):
        display_output("Connected to a wifi network\n")
        create_gui()
    else:
        display_output("Connect to a wifi network\nYou are not connected\n")
        return



#--------------------------------------------------------------------------------------------------------------------------


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

#--------------------------------------------------------------------------------------------------------------------

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
                else:
                    if SERVER_IP is not None:
                        one,two,three,four = SERVER_IP.split('.')
                        one1,two2,three3,four4 = ip_address.split('.')
                        if(one == one1 and two == two2 and three == three3):
                            pass
                        else:
                            display_output("This ip is not in your network\n")
                            continue
            except:
                display_output("The format is wrong. Please enter it again (e.g., 192.168.0.1)\n")
                continue
            
            try:
                try:
                    client_socket.connect((SERVER_IP, 52837))
                    break
                except:
                    client_socket.connect((SERVER_IP,52838))
                    break
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

#--------------------------------------------------------------------------------------------------------------------------------


def about_backend():
    return '''Cipher Link v1.0
Secure file transfer and chat over LAN.
Features:
- Encrypted messaging
- Fast and secure file transfers
- Easy-to-use interface

This application is uses cryptographic and hashing algorithms in order to provide security and privacy over the network.
This application uses AVL Tree, Hashing and Multigraph to share Images,Videos,Files,Text over the local network in an efficient manner.

This app was made for Data Structures Laboratory project by Parithikrishnan and Nirupa.
'''


#------------------------------------------------------------- UI of the page ---------------------------------------------------


def open_new_page(title, backend_func=None):
    global output_window, output_text
    output_window = Toplevel(root)
    output_window.geometry(f"{window_width}x{window_height}+{screen_width//8}+{screen_height//8}")
    output_window.title(title)
    new_bg = Image.open(bg_image_path).resize((window_width, window_height), Image.LANCZOS)
    new_bg_photo = ImageTk.PhotoImage(new_bg)
    new_bg_label = Label(output_window, image=new_bg_photo)
    new_bg_label.image = new_bg_photo
    new_bg_label.place(relwidth=1, relheight=1)
    if title == "Chat":
        if backend_func:
            backend_func()
    else:
        code_frame = Frame(output_window, bg="#0a1a2a", bd=2, highlightbackground="#00b4d8")
        code_frame.place(relwidth=0.9, relheight=0.8, relx=0.05, rely=0.1)

        output_text = Text(code_frame, font=("Courier", 12), fg="white", bg="#0a1a2a",
                           insertbackground="white", wrap="word")
        output_text.pack(fill="both", expand=True, padx=10, pady=10)
        if backend_func and title != "About App":
            def delayed_backend():
                output_window.after(200, backend_func)
            output_window.after(50, delayed_backend)
        elif backend_func:
            output_text.insert("1.0", backend_func())
    back_button = Button(output_window, text="Back", command=output_window.destroy,
                         font=("Arial", 12, "bold"), fg="white", bg="#1a2a3a",
                         activebackground="#00b4d8", activeforeground="black",
                         relief="flat", padx=10, pady=5)
    back_button.place(relx=0.9, rely=0.01)
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

#--------------------------------------------------------------------------------------------------------------------------------