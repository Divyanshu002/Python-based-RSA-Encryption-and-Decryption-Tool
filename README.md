# Python-based-RSA-Encryption-and-Decryption-Tool
Python based RSA Encryption and Decryption Tool is a command-line interface (CLI) application designed to provide secure encryption and decryption functionality using the RSA algorithm. 

# Key Features
* RSA Encryption and Decryption: Utilize the robust RSA encryption algorithm to securely encrypt and decrypt data, ensuring confidentiality and integrity.
* Key Pair Generation: Generate RSA key pairs with customizable parameters, providing the necessary keys for encryption and decryption operations.
* File Encryption and Decryption: Encrypt and decrypt files of any type, enabling secure transmission and storage of sensitive information.
* Command-Line Interface: Intuitive CLI interface for easy integration into scripts and automation workflows, providing flexibility and ease of use.
* Symmetric Key Encryption: Utilize symmetric key encryption with AES for efficient encryption of large data files.
* Password Protection: Optional password protection for RSA private keys, enhancing security and access control.
* Cross-Platform Compatibility: Compatible with major operating systems, including Windows, macOS, and Linux, ensuring broad accessibility and ease of deployment.

# Getting Started
To get started with Python based RSA Encryption and Decryption Tool, follow these steps:
1. Clone the repository:
```python
git clone https://github.com/Divyanshu002/Python-based-RSA-Encryption-and-Decryption-Tool.git
 ```
2. Install the required dependencies:
```python
pip install -r requirements.txt
 ```
3. Generate an RSA key pair:
```python
python Script.py --generate-keypair
 ```
4. Start encrypting and decrypting files using the provided CLI commands.

# Usage
1. Generate RSA key pair:
```python
python Script.py --generate-keypair
 ```
2. Encrypt a file:
```python
python Script.py --encrypt-file input_file_path --output-file-encrypt output_file_path
 ```
3. Decrypt a file:
```python
python Script.py --decrypt-file encrypted_file_path --output-file-decrypt output_file_path
 ```

# License
This project is licensed under the GNU General Public License v3.0 - see the LICENSE file for details.
