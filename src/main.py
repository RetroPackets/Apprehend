# -*- coding: utf-8 -*-

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QTextEdit
from capture import *
from queue import Queue
from datetime import datetime


from PyQt5.QtGui import *
from tkinter import *
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QPushButton, QMessageBox, QAction
from PyQt5 import QtGui
from PyQt5.QtWidgets import QMenu
import os
import subprocess
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtPrintSupport import *
import sys



packet_queue = Queue()


class Stream(QtCore.QObject):
	newText = QtCore.pyqtSignal(str)

	def write(self, text):
		self.newText.emit(str(text))


class snifferGui(QtWidgets.QMainWindow):

	sigStatus = QtCore.pyqtSignal(str)

	def __init__(self, parent = None):
		super(snifferGui, self).__init__(parent)
		self.packetCount = 1


	def setupUi(self, root):

		root.setObjectName("root")
		root.resize(1050, 800)
		root.setLayoutDirection(QtCore.Qt.LeftToRight)
		self.centralwidget = QtWidgets.QWidget(root)
		self.centralwidget.setObjectName("centralwidget")
		
		self.verticalLayout = QtWidgets.QVBoxLayout(self.centralwidget)
		self.verticalLayout.setObjectName("verticalLayout")
		

		self.treeWidget = QtWidgets.QTreeWidget(self.centralwidget)
		self.treeWidget.setObjectName("treeWidget")
		self.treeWidget.setStyleSheet("border: 1px solid red; background-color: black; color: white")
		self.verticalLayout.addWidget(self.treeWidget)

		self.process = QTextEdit(readOnly=True)
		self.process.ensureCursorVisible()
		self.process.setLineWrapColumnOrWidth(500)
		# Set QTextEdit Background Color
		self.process.setStyleSheet( " border: 1px solid black; background-color: black; color: gray")
		self.verticalLayout.addWidget(self.process)

		root.setCentralWidget(self.centralwidget)
		
		self.statusbar = QtWidgets.QStatusBar(root)
		self.statusbar.setObjectName("statusbar")
		root.setStatusBar(self.statusbar)
		
		self.toolBar = QtWidgets.QToolBar(root)
		self.toolBar.setLayoutDirection(QtCore.Qt.LeftToRight)
		self.toolBar.setOrientation(QtCore.Qt.Vertical)
		self.toolBar.setIconSize(QtCore.QSize(30, 30))
		self.toolBar.setToolButtonStyle(QtCore.Qt.ToolButtonIconOnly)
		self.toolBar.setFloatable(True)
		self.toolBar.setObjectName("toolBar")
		root.addToolBar(QtCore.Qt.TopToolBarArea, self.toolBar)

		
		self.menubar = QtWidgets.QMenuBar(root)
		self.menubar.setStyleSheet("border: 1px solid red; background-color: black; color: gray")
		self.menubar.setGeometry(QtCore.QRect(0, 0, 668, 26))
		self.menubar.setObjectName("menubar")
		root.setMenuBar(self.menubar)
		
		self.actionCapture = QtWidgets.QAction(root)
		icon = QtGui.QIcon()
		icon.addPixmap(QtGui.QPixmap("cap.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
		self.actionCapture.setIcon(icon)
		self.actionCapture.setObjectName("actionCapture")
		
		self.actionStop = QtWidgets.QAction(root)
		icon = QtGui.QIcon()
		icon.addPixmap(QtGui.QPixmap("stop.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
		self.actionStop.setIcon(icon)
		self.actionStop.setObjectName("actionStop")
		
		self.actionExit = QtWidgets.QAction(root)
		icon1 = QtGui.QIcon()
		icon1.addPixmap(QtGui.QPixmap("exit.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
		self.actionExit.setIcon(icon1)
		self.actionExit.setObjectName("actionExit")
		
		self.toolBar.addAction(self.actionCapture)
		self.toolBar.addAction(self.actionStop)
		self.toolBar.addAction(self.actionExit)
		self.retranslateUi(root)
		
		self.actionExit.triggered.connect(app.exit)
		self.actionCapture.triggered.connect(self.startCapture)
		self.actionStop.triggered.connect(self.stopCapture)

		QtCore.QMetaObject.connectSlotsByName(root)
		sys.stdout = Stream(newText=self.onUpdateText)

	def onUpdateText(self, text):
		cursor = self.process.textCursor()
		cursor.movePosition(QtGui.QTextCursor.End)
		cursor.insertText(text)
		
		#self.process.selectAll()
		#self.process.setFontPointSize(10)
		
		self.process.setTextCursor(cursor)
		self.process.ensureCursorVisible()

	def __del__(self):
		sys.stdout = sys.__stdout__

	def retranslateUi(self, root):
		_translate = QtCore.QCoreApplication.translate
		root.setWindowTitle(_translate("root", "Apprehend Packet Sniffer"))
		root.setStyleSheet("border: 1px solid black; background-color: black; color: white")


		self.toolBar.setWindowTitle(_translate("root", "toolBar"))
		self.actionCapture.setText(_translate("root", "Start"))
		self.actionCapture.setToolTip(_translate("root", "Capture Packets"))
		self.actionStop.setText(_translate("root", "Stop"))
		self.actionStop.setToolTip(_translate("root", "Stop Capture"))
		self.actionExit.setText(_translate("root", "Exit"))
		self.actionExit.setToolTip(_translate("root", "Quit"))
		
		
		
		self.treeWidget.setSortingEnabled(True)
		self.treeWidget.headerItem().setText(0, _translate("root", "TIME"))
		self.treeWidget.headerItem().setText(1, _translate("root", "NUMBER"))
		self.treeWidget.headerItem().setText(2, _translate("root", "SOURCE"))
		self.treeWidget.setColumnWidth(2, 125)
		self.treeWidget.headerItem().setText(3, _translate("root", "DESTINATION"))
		self.treeWidget.setColumnWidth(3, 125)
		self.treeWidget.headerItem().setText(4, _translate("root", "PROTOCOL"))




	def startCapture(self):

		# Create Socket.
		self.sock, self.pcap = create_socket()
		self.getPacketThread = GetPacketThread(self.sock, self.pcap)
		self.getPacketThread.start()
		# Connect Qthread signals
		self.getPacketThread.sigStatus.connect(self.showPacket)


	def stopCapture(self):

		if self.getPacketThread.running == True:
			# Terminate thread
			self.getPacketThread.running = False

			print('Stopping capture...')
			self.getPacketThread.terminate()
				
			# Wait for termination
			print('Waiting for thread termination...')
			self.getPacketThread.wait()

			# emit closing signal
			self.sigStatus.emit('stopExtPkt')

			# close socket and pcap
			print('Closing socket and pcap...')
			self.pcap.close()
			self.sock.close()
			print('Capture stopped!')
		else:
			print('Capture not started!')


	def showPacket(self):

		while packet_queue.qsize() > 0:

			pack = packet_queue.get()
			eth = Ethernet(pack)

			# IPv4
			if eth.proto == 8:
				ipv4 = IPv4(eth.data)
				item = QtWidgets.QTreeWidgetItem(self.treeWidget, [str(datetime.now().strftime('%H:%M:%S')), str(self.packetCount), ipv4.src, ipv4.target, ipv4.next_proto])
				sys.stdout.write(
					f"\n\n\nPacket #{self.packetCount}\tPacket Length: {eth.pac_len}\n"
				)
				sys.stdout.write(
					f"{ethFrame}\n\nSource MAC: {eth.src_mac}\tDestination MAC: {eth.dest_mac}\tNetwork Protocol:IPv4  \tTransport Protocol: {ipv4.next_proto}\n{sep1}\n\n"
				)
				self.packetCount += 1
				# ICMP
				if ipv4.proto == 1:
					icmp = ICMP(ipv4.data)
					sys.stdout.write(
						f"Type: {icmp.type} \t Code: {icmp.code} \t Checksum: {icmp.checksum}\n{sep1}\n"
					)
					try:
						sys.stdout.write(f"ICMP data:\n{icmp.data.decode('utf-8')}\n{sep1}\n")
					except UnicodeDecodeError:
						pass

				elif ipv4.proto == 6:
					tcp = TCP(ipv4.data)
					sys.stdout.write(
						f"Source Port: {tcp.src_port} \t Destination Port: {tcp.dest_port} \t Sequence: {tcp.sequence}\t Acknowledgment: {tcp.acknowledgment}\n\nFlags: \tURG: {tcp.flag_URG} \t ACK: {tcp.flag_ACK} \t PSH: {tcp.flag_PSH} \t RST: {tcp.flag_RST} \t SYN: {tcp.flag_SYN} \t FIN:{tcp.flag_FIN}\n{sep1}\n"
					)
					if tcp.src_port == 80 or tcp.dest_port == 80:
						if len(tcp.data) > 0:
							try:
								sys.stdout.write(f"TCP data:\n{tcp.data.decode('utf-8')}\n{sep1}\n")
							except UnicodeDecodeError:
								pass

				elif ipv4.proto == 17:
					udp = UDP(ipv4.data)
					sys.stdout.write(
						f"Source Port: {udp.src_port} \t Destination Port: {udp.dest_port} \t Length: {udp.length} \t Checksum: {udp.checksum}\n{sep1}\n "
					)
					try:
						sys.stdout.write(f"UDP data:\n{udp.data.decode('utf-8')}\n{sep1}\n")
					except UnicodeDecodeError:
						pass

				else:
					try:
						sys.stdout.write(f"IPv4 data:\n{ipv4.data.decode('utf-8')}\n{sep1}\n")
					except UnicodeDecodeError:
						pass

			else:
				try:
					sys.stdout.write(f"Ethernet data:\n{eth.data.decode('utf-8')}\n{sep1}\n")
				except UnicodeDecodeError:
					pass


class GetPacketThread(QtCore.QThread):

	sigStatus = QtCore.pyqtSignal(str)

	def __init__(self, sock, pcap, parent= None):
		super(GetPacketThread, self).__init__(parent)
		self.sock = sock
		self.pcap = pcap

	def run(self):

		self.running = True
		print("Capture Started")
		# Start packet extraction and emit signal to main gui thread. 
		while self.running:

			self.pack = extract_socket(self.sock)
			self.pcap.write(self.pack)
			packet_queue.put(self.pack)
			self.sigStatus.emit("showPacket")


	
if __name__ == "__main__":
	import sys
	app = QtWidgets.QApplication(sys.argv)
	
	qp = QPalette()
	qp.setColor(QPalette.ButtonText, Qt.white)
	qp.setColor(QPalette.WindowText, Qt.red)
	qp.setColor(QPalette.Window, Qt.black)
	qp.setColor(QPalette.Button, Qt.black)
	qp.setColor(QPalette.Foreground, Qt.white)
	qp.setColor(QPalette.Base, Qt.red)
	qp.setColor(QPalette.Text, Qt.white)
	qp.setColor(QPalette.Light, Qt.white)
	qp.setColor(QPalette.Dark, Qt.red)
	qp.setColor(QPalette.Shadow, Qt.black)
	qp.setColor(QPalette.Highlight, Qt.black)
	qp.setColor(QPalette.HighlightedText, Qt.red)
	
	

	app.setPalette(qp)
	app.setStyle("Fusion")
	app.setWindowIcon(QtGui.QIcon('icon_photo.png'))
	
	root = QtWidgets.QMainWindow()
	ui = snifferGui()
	ui.setupUi(root)
	root.show()
	sys.exit(app.exec_())
