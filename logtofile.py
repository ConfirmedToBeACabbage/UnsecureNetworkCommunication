file_name = "output.txt"
mode = 'w'

def initfilesend(): 
    global file_name 
    global mode
    with open(file_name, mode) as file:
        file.write('BEGIN\n')
        file.close()
    
    mode = 'a'    
    

def printtofile(msg): 
    global file_name
    global mode
    with open(file_name, mode) as file: 
        file.write(msg + '\n')
        file.close()
