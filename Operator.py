
import subprocess, threading

PAYLOAD_SIZE = 1024
HEADER_SIZE = 18 #6*3

PROCESSED_FILE = "toArch.dat" 


failed =0

class Command(object):
    def __init__(self, cmd):
        self.cmd = cmd
        self.process = None

    def run(self, timeout):
        def target():
            print 'Thread started'
            self.process = subprocess.Popen(self.cmd)
            self.process.communicate()
            print 'Thread finished'

        thread = threading.Thread(target=target)
        thread.start()
        global failed
        thread.join(timeout)
        if thread.is_alive():
            failed = 1
            self.process.terminate()
            thread.join()
        print self.process.returncode

def create_headers(string, payload_size, header_size):

	datas = []
	payloads = []
	message = string[:]
	payload_num = len(string) / payload_size

	for i in range(len(string)):
		if (len(string[len(datas)*(payload_size - header_size):]) < payload_size - header_size):
			datas.append(string[len(datas)*(payload_size - header_size):])
			break
		if (i % (payload_size - header_size) == 0):
			datas.append(string[len(datas)*(payload_size -header_size):len(datas)*(payload_size -header_size)+ payload_size - header_size])
	for i in range(1,len(datas)+1):
		payload = str(len(string)).zfill(header_size/3)+str(i).zfill(header_size/3)+str(len(datas)).zfill(header_size/3)+datas[i-1]
		payloads.append(payload)

	return payloads


def recv_trans_from_file(file_name):
	f = open(file_name, "r")
	trans = f.read()
	f.close()
	return trans.strip()


def operate_netconnect(transmission, netconnect, result_file):
	""" Open netconnect, send transmission. pull data until less than 1kb is sent """
 	payloads = create_headers(transmission, PAYLOAD_SIZE, HEADER_SIZE)
 	final_file = open(PROCESSED_FILE,"a+")
	for payload in payloads:
		#call netconnect with payload
		args = (netconnect, result_file, payload)
		print args
		
		command = Command(args)
		command.run(timeout=1)

		clean_result = get_clean_result(result_file,payload)
		final_file.write(clean_result)
		if len(clean_result) == 0:
			return

		if (failed == 1):
			#restart command, until "get_remaining_bytes" is less than Kb
			clean_file(transmission, result_file)
			bytes_left = get_remaining_bytes(result_file) * -1
			while bytes_left >= 1000:
				command = Command(args)
				command.run(timeout=1)
				clean_file(transmission, result_file)
				bytes_left = get_remaining_bytes(result_file) * -1

				clean_result = get_clean_result(result_file, payload)
				final_file.write(clean_result)

			global failed
			failed = 0
	final_file.close()

def get_clean_result(result_file, transmission):
	res = open(result_file, "r")
	data = res.read()
	data = data.split(transmission)
	print data
	res.close()
	#now open for write, essentialy cleaning file
	res = open(result_file, "w")
	res.close()
	return "".join(data)

def clean_file(transmission, result_file):
	res = open(result_file,"r")
	data = res.read()
	data.split(transmission)
	res.close()
	res = open(result_file,"w")
	res.write("".join(data))
	res.close()


def get_remaining_bytes(result_file):
	rec = open("bytes_read.txt","r")
	bytes_read = rec.read().strip()
	bytes_read = int(bytes_read)
	res = open(result_file,"r")
	recieved = len(res.read()) - bytes_read
	return recieved


failed = 0
trans = recv_trans_from_file("NetCommands.txt")
operate_netconnect(trans, "./NetConnect1", "res.txt")


