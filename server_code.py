import socket as s
import threading as t
import time

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
        with open("avl_chat_tree.txt", "w") as f:
            self.save_tree_structure(self.root, f)
    def save_tree_structure(self, node, f, level=0, prefix="Root: "):
        if node is not None:
            self.save_tree_structure(node.right, f, level + 1, "R---- ")
            f.write("     " * level + prefix + f"[{node.key}] {node.message}\n")
            self.save_tree_structure(node.left, f, level + 1, "L---- ")

def display_output(msg):
    print(msg)

checking = True

if checking:
    display_output("The system is connected to the local network\n")
    choice = input("Create a chat server\nJoin in a chat server\n>> ")
    if(choice == '1'):
        server_socket = s.socket(s.AF_INET, s.SOCK_STREAM)
        server_socket.bind(('0.0.0.0', 5293))
        display_output("The server is started and listening\n")
        username = input("Enter your name: ")
        server_socket.listen(1)
        conn, addr = server_socket.accept()
        display_output(f"{addr} is connected to the server\n")
        username_of = conn.recv(1024).decode('utf-8')
        conn.send(username.encode('utf-8'))
        display_output(f"The name of person from {addr} is {username_of}\n")
        tree = AVLTree()
        display_output("You can now start chatting\n")
        def handle_receive():
            while True:
                try:
                    msg = conn.recv(1024).decode()
                    if msg:
                        timestamp = int(time.time())
                        tree.add_message(timestamp, f"{username_of}: {msg}")
                        print(f"\n{username_of}: {msg}")
                except:
                    break
        def handle_send():
            while True:
                message = input('>> ')
                conn.send(message.encode())
                timestamp = int(time.time())
                tree.add_message(timestamp, f"{username}: {message}")
        t.Thread(target=handle_receive).start()
        t.Thread(target=handle_send).start()
    elif(choice == '2'):
        client_socket = s.socket(s.AF_INET, s.SOCK_STREAM)
        ip = '127.0.0.1'
        client_socket.connect((ip, 5293))
        display_output("Connected to the server\n")
        username = input("Enter your name: ")
        client_socket.send(username.encode('utf-8'))
        username_of = client_socket.recv(1024).decode('utf-8')
        display_output(f"The name of person from server is {username_of}\n")
        tree = AVLTree()
        display_output("You can now start chatting\n")
        def handle_receive():
            while True:
                try:
                    msg = client_socket.recv(1024).decode()
                    if msg:
                        timestamp = int(time.time())
                        tree.add_message(timestamp, f"{username_of}: {msg}")
                        print(f"\n{username_of}: {msg}")
                except:
                    break
        def handle_send():
            while True:
                message = input('>> ')
                client_socket.send(message.encode())
                timestamp = int(time.time())
                tree.add_message(timestamp, f"{username}: {message}")
        t.Thread(target=handle_receive).start()
        t.Thread(target=handle_send).start()
else:
    display_output("The system is not connected to the local network\n")
