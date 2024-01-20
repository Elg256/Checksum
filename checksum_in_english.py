import sys
import hashlib
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QFileDialog
from PyQt5.QtCore import Qt


class FileHasher(QWidget):
    # Create an cache were each time we calculate the hash of a file, we store the result in the
    # cache along with the alg used.
    cache = {}
    
    def __init__(self):
        super().__init__()
        
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout()
        
        self.label = QLabel('Select a file to calculate the hash')
        layout.addWidget(self.label)
        
        select_button = QPushButton('Select a file')
        select_button.clicked.connect(self.showDialog)
        select_button.setFixedSize(400, 30)  # Définir la taille du bouton
        layout.addWidget(select_button)
        
        sha256_button = QPushButton('Calculate SHA-256')
        sha256_button.clicked.connect(self.calculateHashSHA256)
        sha256_button.setFixedSize(400, 30)  # Définir la taille du bouton
        layout.addWidget(sha256_button)
        
        # Ajout du label "autres:"
        other_label = QLabel('Others:')
        other_label.setAlignment(Qt.AlignCenter)  # Alignement au centre
        layout.addWidget(other_label)
        
        sha512_button = QPushButton('Calculate SHA-512')
        sha512_button.clicked.connect(self.calculateHashSHA512)
        sha512_button.setFixedSize(400, 30)  # Définir la taille du bouton
        layout.addWidget(sha512_button)
        
        md5_button = QPushButton('Calculate MD5')
        md5_button.clicked.connect(self.calculateHashMD5)
        md5_button.setFixedSize(400, 30)  # Définir la taille du bouton
        layout.addWidget(md5_button)
        
        self.result_label = QLabel('')
        layout.addWidget(self.result_label)
        
        self.setLayout(layout)
        
        # Appliquer le style aux boutons
        select_button.setStyleSheet("background-color: #4CAF50; color: white;")
        sha256_button.setStyleSheet("background-color: #008CBA; color: white;")
        sha512_button.setStyleSheet(
            "background-color: #FFD700; color: black;"
            )  # Couleur dorée pour SHA-512
        md5_button.setStyleSheet(
            "background-color: #CD5C5C; color: white;"
            )  # Couleur rouge pour MD5
    
    def showDialog(self):
        fname = QFileDialog.getOpenFileName(self, 'Select a file')[0]
        self.label.setText(f'Selected file : {fname}')
        self.file_path = fname
    
    def calculateHashSHA256(self):
        self.calculateHash(hashlib.sha256, 'SHA-256')
    
    def calculateHashSHA512(self):
        self.calculateHash(hashlib.sha512, 'SHA-512')
    
    def calculateHashMD5(self):
        self.calculateHash(hashlib.md5, 'MD5')
    
    def calculateHash(self, hash_function, algorithm):
        if self.file_path in self.cache:
            if self.cache[self.file_path]['alg'] == algorithm:
                self.result_label.setText(f'{algorithm} : {self.cache[self.file_path]["hash"]}')
                return
        
        try:
            with open(self.file_path, 'rb') as f:
                hash_obj = hash_function()
                while chunk := f.read(8192):
                    hash_obj.update(chunk)
            
            hex_digest = hash_obj.hexdigest()
            self.cache[self.file_path] = {'alg': algorithm, 'hash': hex_digest}
            self.result_label.setText(f'{algorithm} : {hex_digest}')
        
        except AttributeError:
            self.result_label.setText(f'Please select a file before calculating the {algorithm}.')


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = FileHasher()
    ex.setWindowTitle('Hash Calculator')
    ex.setGeometry(100, 100, 400, 250)
    ex.show()
    sys.exit(app.exec_())
