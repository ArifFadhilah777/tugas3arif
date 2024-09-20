import tkinter as tk
from tkinter import filedialog, messagebox
import numpy as np

# Fungsi untuk enkripsi dan dekripsi Vigenere Cipher
def vigenere_encrypt(plaintext, key):
    ciphertext = ''
    key = key.lower()
    key_length = len(key)
    
    for i, char in enumerate(plaintext):
        if char.isalpha():
            shift = ord(key[i % key_length]) - ord('a')
            if char.islower():
                ciphertext += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            else:
                ciphertext += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
        else:
            ciphertext += char
    return ciphertext

def vigenere_decrypt(ciphertext, key):
    plaintext = ''
    key = key.lower()
    key_length = len(key)
    
    for i, char in enumerate(ciphertext):
        if char.isalpha():
            shift = ord(key[i % key_length]) - ord('a')
            if char.islower():
                plaintext += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            else:
                plaintext += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
        else:
            plaintext += char
    return plaintext

# Fungsi untuk enkripsi dan dekripsi Playfair Cipher
def generate_playfair_matrix(key):
    key = key.lower().replace("j", "i")  # Mengganti 'j' dengan 'i' sesuai aturan Playfair
    matrix = []
    used_chars = set()
    
    for char in key:
        if char not in used_chars and char.isalpha():
            matrix.append(char)
            used_chars.add(char)
    
    alphabet = "abcdefghiklmnopqrstuvwxyz"  # 'j' tidak digunakan
    for char in alphabet:
        if char not in used_chars:
            matrix.append(char)
            used_chars.add(char)
    
    return [matrix[i:i + 5] for i in range(0, 25, 5)]

def find_position(char, matrix):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == char:
                return row, col
    return None

def prepare_text(plaintext):
    plaintext = plaintext.lower().replace("j", "i")  # Mengganti 'j' dengan 'i'
    prepared_text = ""
    i = 0
    
    while i < len(plaintext):
        char1 = plaintext[i]
        char2 = plaintext[i + 1] if i + 1 < len(plaintext) else 'x'
        
        if char1 == char2:  # Jika dua huruf sama, tambahkan 'x' di antaranya
            prepared_text += char1 + 'x'
            i += 1
        else:
            prepared_text += char1 + char2
            i += 2

    if len(prepared_text) % 2 != 0:  # Jika jumlah huruf ganjil, tambahkan 'x' di akhir
        prepared_text += 'x'
    
    return prepared_text

def playfair_encrypt(plaintext, key):
    matrix = generate_playfair_matrix(key)
    plaintext = prepare_text(plaintext)
    ciphertext = ""
    
    for i in range(0, len(plaintext), 2):
        char1, char2 = plaintext[i], plaintext[i+1]
        row1, col1 = find_position(char1, matrix)
        row2, col2 = find_position(char2, matrix)
        
        if row1 == row2:  # Jika berada di baris yang sama, geser ke kanan
            ciphertext += matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:  # Jika berada di kolom yang sama, geser ke bawah
            ciphertext += matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
        else:  # Jika berada di baris dan kolom yang berbeda, tukar menjadi persegi
            ciphertext += matrix[row1][col2] + matrix[row2][col1]
    
    return ciphertext

def playfair_decrypt(ciphertext, key):
    matrix = generate_playfair_matrix(key)
    plaintext = ""
    
    for i in range(0, len(ciphertext), 2):
        char1, char2 = ciphertext[i], ciphertext[i+1]
        row1, col1 = find_position(char1, matrix)
        row2, col2 = find_position(char2, matrix)
        
        if row1 == row2:  # Jika berada di baris yang sama, geser ke kiri
            plaintext += matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:  # Jika berada di kolom yang sama, geser ke atas
            plaintext += matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2]
        else:  # Jika berada di baris dan kolom yang berbeda, tukar menjadi persegi
            plaintext += matrix[row1][col2] + matrix[row2][col1]
    
    return plaintext


# Fungsi untuk enkripsi dan dekripsi Hill Cipher
def mod_inverse_matrix(matrix, mod):
    det = int(np.round(np.linalg.det(matrix)))  # Determinan dari matriks
    det_inv = mod_inverse(det % mod, mod)  # Invers dari determinan
    matrix_mod_inv = (
        det_inv * np.round(det * np.linalg.inv(matrix)).astype(int) % mod
    )  # Invers matriks mod 26
    return matrix_mod_inv % mod

def mod_inverse(a, m):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    raise ValueError(f"Tidak ada invers untuk {a} di mod {m}")

def text_to_vector(text, block_size):
    vector = [ord(char) - ord('a') for char in text.lower() if char.isalpha()]
    
    while len(vector) % block_size != 0:  # Tambahkan 'x' jika panjang teks tidak sesuai dengan ukuran blok
        vector.append(ord('x') - ord('a'))
    
    return np.array(vector).reshape(-1, block_size)

def vector_to_text(vector):
    text = ''.join(chr(int(num) + ord('a')) for num in vector.flatten())
    return text

def hill_encrypt(plaintext, key):
    block_size = key.shape[0]
    plaintext_vector = text_to_vector(plaintext, block_size)
    ciphertext_vector = (np.dot(plaintext_vector, key) % 26).flatten()  # Operasi perkalian matriks mod 26
    ciphertext = vector_to_text(ciphertext_vector)
    return ciphertext

def hill_decrypt(ciphertext, key):
    block_size = key.shape[0]
    ciphertext_vector = text_to_vector(ciphertext, block_size)
    key_inverse = mod_inverse_matrix(key, 26)  # Invers dari kunci mod 26
    plaintext_vector = (np.dot(ciphertext_vector, key_inverse) % 26).flatten()
    plaintext = vector_to_text(plaintext_vector)
    return plaintext

# Fungsi untuk membaca file
def open_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, 'r') as file:
            content = file.read()
        text_input.delete(1.0, tk.END)
        text_input.insert(tk.END, content)

# Fungsi untuk menyimpan hasil ke file
def save_file(content):
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, 'w') as file:
            file.write(content)

# Fungsi untuk memanggil cipher yang dipilih
def encrypt_message():
    plaintext = text_input.get("1.0", tk.END).strip()
    key = key_input.get().strip()
    
    if len(key) < 12:
        messagebox.showerror("Error", "Kunci harus minimal 12 karakter!")
        return
    
    cipher_choice = cipher_var.get()
    
    if cipher_choice == "Vigenere":
        ciphertext = vigenere_encrypt(plaintext, key)
    elif cipher_choice == "Playfair":
        ciphertext = playfair_encrypt(plaintext, key)
    elif cipher_choice == "Hill":
        ciphertext = hill_encrypt(plaintext, key)
    
    text_output.delete(1.0, tk.END)
    text_output.insert(tk.END, ciphertext)

def decrypt_message():
    ciphertext = text_input.get("1.0", tk.END).strip()
    key = key_input.get().strip()
    
    if len(key) < 12:
        messagebox.showerror("Error", "Kunci harus minimal 12 karakter!")
        return
    
    cipher_choice = cipher_var.get()
    
    if cipher_choice == "Vigenere":
        plaintext = vigenere_decrypt(ciphertext, key)
    elif cipher_choice == "Playfair":
        plaintext = playfair_decrypt(ciphertext, key)
    elif cipher_choice == "Hill":
        plaintext = hill_decrypt(ciphertext, key)
    
    text_output.delete(1.0, tk.END)
    text_output.insert(tk.END, plaintext)

# GUI dengan Tkinter
root = tk.Tk()
root.title("Cryptography Program")

# Label dan input teks
tk.Label(root, text="Masukkan Pesan:").grid(row=0, column=0, padx=10, pady=10)
text_input = tk.Text(root, height=3, width=50)
text_input.grid(row=1, column=0, padx=10, pady=10)

tk.Label(root, text="Masukkan Kunci (minimal 12 karakter):").grid(row=2, column=0, padx=10, pady=10)
key_input = tk.Entry(root, width=50)
key_input.grid(row=3, column=0, padx=10, pady=10)

# Opsi untuk memilih algoritma cipher
cipher_var = tk.StringVar(value="Vigenere")  # Default Vigenere

tk.Label(root, text="Pilih Cipher:").grid(row=4, column=0, padx=10, pady=10)
vigenere_rb = tk.Radiobutton(root, text="Vigenere Cipher", variable=cipher_var, value="Vigenere")
vigenere_rb.grid(row=5, column=0, padx=10, sticky="w")
playfair_rb = tk.Radiobutton(root, text="Playfair Cipher", variable=cipher_var, value="Playfair")
playfair_rb.grid(row=6, column=0, padx=10, sticky="w")
hill_rb = tk.Radiobutton(root, text="Hill Cipher", variable=cipher_var, value="Hill")
hill_rb.grid(row=7, column=0, padx=10, sticky="w")

# Tombol untuk enkripsi, dekripsi, dan file
tk.Button(root, text="Buka File", command=open_file).grid(row=8, column=0, padx=10, pady=10)
tk.Button(root, text="Simpan Hasil", command=lambda: save_file(text_output.get("1.0", tk.END))).grid(row=9, column=0, padx=10, pady=10)
tk.Button(root, text="Enkripsi", command=encrypt_message).grid(row=10, column=0, padx=10, pady=10)
tk.Button(root, text="Dekripsi", command=decrypt_message).grid(row=11, column=0, padx=10, pady=10)

# Output area
tk.Label(root, text="Hasil:").grid(row=12, column=0, padx=10, pady=10)
text_output = tk.Text(root, height=3, width=50)
text_output.grid(row=13, column=0, padx=10, pady=10)

# Jalankan aplikasi
root.mainloop()

