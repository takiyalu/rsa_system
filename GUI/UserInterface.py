import streamlit as st
from basisClasses.RSA import RSA

class UserInterface:
    def __init__(self):
        self.__private_key, self.__public_key = RSA.generate_rsa_key_pair()
        self.__uploaded_file = None
        self.__private_key_txt = ""
        self.__public_key_txt = ""
        self.__integrity_analysis_txt = ""

    def runInterface(self):
        st.title("RSA File Transfer System")
        self.key_generation()
        self.upload_file()
        self.encryptionDecryption()

    def key_generation(self):
        if st.button("Generate Keys"):
            RSA.save_private_key('private_key', self.__private_key)
            RSA.save_public_key('public_key', self.__public_key)
            with open('private_key', 'r') as private:
                self.__private_key_txt = private.read()
            with open('public_key', 'r') as public:
                self.__public_key_txt = public.read()
                print(self.__public_key_txt)

            st.text_area("Private Key", value=self.__private_key_txt, height=10)
            st.text_area("Public Key", value=self.__public_key_txt, height=10)
            st.download_button(label="Save Public Key", data=self.__public_key_txt,
                               file_name="public_key.txt")

    def upload_file(self):
        # Upload file
        self.__uploaded_file = st.file_uploader("Upload File")

    def encryptionDecryption(self):
        # Select encryption or decryption
        encryption_choice = st.selectbox("Choose an option:", ["Encrypt", "Decrypt"])
        # Perform encryption or decryption
        if self.__uploaded_file is not None:
            if encryption_choice == "Encrypt":
                key_choice = st.selectbox("Choose an option:", ["Generated public key", "Imported public key"])
                if key_choice == "Imported public key":
                    upload_public_key = st.file_uploader("Public Key")
                    loaded_key = RSA.load_public_key(file=upload_public_key)
                else:
                    loaded_key = RSA.load_public_key(path='public_key')
                if st.button("Encrypt File"):
                    encrypted_file = RSA.encrypt_file(self.__uploaded_file, loaded_key)
                    st.download_button(label="Download Encrypted File", data=encrypted_file,
                                       file_name="encrypted_file.txt")

            elif encryption_choice == "Decrypt":
                key_choice = st.selectbox("Choose an option:", ["Generated private key", "Imported private key"])
                if key_choice == "Imported private key":
                    upload_private_key = st.file_uploader("Private_Key")
                    loaded_key = RSA.load_private_key(file=upload_private_key)
                else:
                    loaded_key = RSA.load_private_key(path='private_key')
                if st.button("Decrypt file"):
                    decrypted_file = RSA.decrypt_file(self.__uploaded_file, loaded_key)
                    st.download_button(label="Download Decrypted File", data=decrypted_file,
                                       file_name="decrypted_file.txt")
                    integrity_analysis = RSA.integrity_verification(decrypted_file, 'hashed_file')
                    st.text_area("Integrity Analysis", value=integrity_analysis, height=10)