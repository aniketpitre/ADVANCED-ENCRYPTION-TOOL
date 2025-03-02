import sys
import os
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QLabel, QLineEdit, QPushButton,
    QFileDialog, QVBoxLayout, QHBoxLayout, QMessageBox, QProgressBar
)
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtGui import QFont

# Import backend functions
from advanced_encryption_tool import encrypt_file, decrypt_file


# Background Worker for Encryption/Decryption
class WorkerThread(QThread):
    finished = pyqtSignal(str)

    def __init__(self, mode, input_file, output_file, password):
        super().__init__()
        self.mode = mode
        self.input_file = input_file
        self.output_file = output_file
        self.password = password

    def run(self):
        try:
            if self.mode == "encrypt":
                encrypt_file(self.input_file, self.output_file, self.password)
            else:
                decrypt_file(self.input_file, self.output_file, self.password)

            self.finished.emit(f"Success: {self.mode.capitalize()}ion complete!")
        except Exception as e:
            self.finished.emit(f"Error: {str(e)}")


# Encryption/Decryption Tab
class EncryptionTab(QWidget):
    def __init__(self, mode):
        super().__init__()
        self.mode = mode
        self.init_ui()

    def init_ui(self):
        # File selection UI
        self.fileLabel = QLabel("Select File:")
        self.fileLineEdit = QLineEdit()
        self.fileLineEdit.setPlaceholderText("Browse or drag & drop a file...")
        self.fileLineEdit.setReadOnly(True)
        self.browseButton = QPushButton("Browse")
        self.browseButton.clicked.connect(self.browse_file)

        fileLayout = QHBoxLayout()
        fileLayout.addWidget(self.fileLineEdit)
        fileLayout.addWidget(self.browseButton)

        # Password input
        self.passwordLabel = QLabel("Enter Password:")
        self.passwordLineEdit = QLineEdit()
        self.passwordLineEdit.setEchoMode(QLineEdit.EchoMode.Password)

        # Custom filename input (only for decryption)
        self.outputFileLabel = QLabel("Enter Output Filename (with extension):")
        self.outputFileLineEdit = QLineEdit()
        if self.mode == "encrypt":
            self.outputFileLabel.hide()
            self.outputFileLineEdit.hide()

        # Encrypt/Decrypt Button
        self.actionButton = QPushButton(f"{self.mode.capitalize()} File")
        self.actionButton.clicked.connect(self.start_action)

        # Progress Bar
        self.progressBar = QProgressBar()
        self.progressBar.setTextVisible(False)
        self.progressBar.setValue(0)

        # Layout
        layout = QVBoxLayout()
        layout.addWidget(self.fileLabel)
        layout.addLayout(fileLayout)
        layout.addWidget(self.passwordLabel)
        layout.addWidget(self.passwordLineEdit)

        if self.mode == "decrypt":
            layout.addWidget(self.outputFileLabel)
            layout.addWidget(self.outputFileLineEdit)

        layout.addWidget(self.actionButton)
        layout.addWidget(self.progressBar)
        self.setLayout(layout)

        # macOS-like UI Styles
        self.setStyleSheet("""
            QLabel { font-size: 14px; }
            QLineEdit { font-size: 14px; padding: 8px; border-radius: 5px; border: 1px solid #ccc; }
            QPushButton { 
                font-size: 14px; padding: 10px; border-radius: 8px; 
                background-color: #007aff; color: white; 
            }
            QPushButton:hover { background-color: #005ecb; }
            QProgressBar { height: 8px; border-radius: 4px; }
        """)

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, f"Select File to {self.mode.capitalize()}")
        if file_path:
            self.fileLineEdit.setText(file_path)

    def generate_output_filename(self, input_path):
        base, ext = os.path.splitext(input_path)
        return f"{base}.enc" if self.mode == "encrypt" else None  # No auto filename for decryption

    def start_action(self):
        input_path = self.fileLineEdit.text().strip()
        password = self.passwordLineEdit.text().strip()

        if not input_path or not password:
            QMessageBox.warning(self, "Missing Information", "All fields must be filled!")
            return

        # For encryption, generate filename automatically
        if self.mode == "encrypt":
            output_path = self.generate_output_filename(input_path)
        else:
            output_path = self.outputFileLineEdit.text().strip()
            if not output_path:
                QMessageBox.warning(self, "Missing Information", "Please enter an output filename with an extension.")
                return

        self.progressBar.setValue(20)

        self.worker = WorkerThread(self.mode, input_path, output_path, password)
        self.worker.finished.connect(self.on_finished)
        self.worker.start()

    def on_finished(self, message):
        self.progressBar.setValue(100)
        QMessageBox.information(self, "Process Complete", message)


# Main UI Window
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Encryption Tool")
        self.setGeometry(100, 100, 500, 300)
        self.init_ui()

    def init_ui(self):
        tabs = QTabWidget()
        tabs.addTab(EncryptionTab("encrypt"), "Encrypt")
        tabs.addTab(EncryptionTab("decrypt"), "Decrypt")
        self.setCentralWidget(tabs)

        # macOS-like UI
        self.setStyleSheet("""
            QMainWindow { background: #f8f8f8; }
            QTabWidget::pane { border: 1px solid #ddd; background: white; }
            QTabBar::tab { padding: 10px; font-size: 14px; }
            QTabBar::tab:selected { background: #e5e5e5; border-radius: 5px; }
        """)


# Run the Application
def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
