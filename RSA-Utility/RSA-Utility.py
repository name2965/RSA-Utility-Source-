from tkinter import *
from tkinter import filedialog
from tkinter.ttk import *
from tkhtmlview import HTMLLabel
import os
import random
from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes, inverse



def make_rand():
    table = "0123456789abcdef"
    res = ''
    for i in range(16):
        res += random.choice(table)
    return res



def create_private_public_pem(bit,label2):
    private_key = RSA.generate(bit)
    public_key = private_key.publickey()
    try:
        rand = make_rand()
        filePath = []

        private_filePath = os.path.dirname(os.path.realpath(__file__)) + '\\' + rand + '_' + 'private_key' + '.pem'
        with open(private_filePath,'wb+') as f:
            f.write(private_key.exportKey('PEM'))
            filePath.append(private_filePath)
            
        public_filePath = os.path.dirname(os.path.realpath(__file__)) + '\\' + rand + '_' + 'public_key' + '.pem'
        with open(public_filePath,'wb+') as f:
            f.write(public_key.exportKey('PEM'))
            filePath.append(public_filePath)
        label2.config(text='private/public pem key generation Success')
        return
    except:
        label2.config(text='private/public pem key generation fail... try again')
        return 



def extract_key(label2):
    file_path = filedialog.askopenfilename(initialdir='./RSA-Utility',title='파일선택',filetypes=(('pem files','*.pem'),('all files','*.*')))
    
    f = open(file_path,'r')
    num_key = RSA.import_key(f.read())
    f.close()
    try:
        extract_filePath = os.path.dirname(os.path.realpath(__file__)) + '/' + os.path.basename(file_path)[0:17] + 'extract_' + os.path.basename(file_path)[17:-4] + '.txt'
        f = open(extract_filePath,'w+')

        try:
            f.write("n = "+str(num_key.n)+'\n\n')
        except:
            pass
        try:
            f.write("e = "+str(num_key.e)+'\n\n')
        except:
            pass
        try:
            f.write("p = "+str(num_key.p)+'\n\n')
        except:
            pass
        try:    
            f.write("q = "+str(num_key.q)+'\n\n')
        except:
            pass
        try:
            f.write("d = "+str(num_key.d)+'\n\n')
        except:
            pass
        try:
            f.write("u = "+str(num_key.u)+'\n\n')
        except:
            pass
        f.close()
        label2.config(text='extract key Success')
    except:
        label2.config(text='extract key fail.... try again')



def extract_key_window():
    instance_window = Toplevel()
    global label2
    w = 300
    h = 100
    ws = instance_window.winfo_screenwidth()
    hs = instance_window.winfo_screenheight()
    x = (ws/2) - (w/2)
    y = (hs/2) - (h/2)

    instance_window.title("Extract Key")
    instance_window.geometry('%dx%d+%d+%d' % (w,h,x,y))
    instance_window.resizable(width=FALSE,height=FALSE)

    label1 = Label(instance_window,text='Choose your key file')
    label2 = Label(instance_window,text='')
    button1 = Button(instance_window,text='Browse...',command = lambda : extract_key(label2))

    label1.grid(row=4,column=3)
    button1.grid(row=4,column=4)
    label2.grid(row=5,column=4)



def encrypt(m,e,n,label):
    rand = make_rand()
    filePath = os.path.dirname(os.path.realpath(__file__)) + '/' + rand + '_encrypt_data.txt'
    try:
        c = pow(int(m),int(e),int(n))
        with open(filePath,'w+') as f:
            f.write('enc_data : '+str(c))
        label.config(text='Encryption Success'+'\n')
    except:
        label.config(text='Encryption fail... try again')



def decrypt(c,d,n,label):
    rand = make_rand()
    filePath = os.path.dirname(os.path.realpath(__file__)) + '/' + rand + '_decrypt_data.txt'
    try:
        m = pow(int(c),int(d),int(n))
        with open(filePath,'w+') as f:
            f.write('dec_data : '+str(m))
        label.config(text='Decryption Success'+'\n')
    except:
        label.config(text='Decryption fail... try again')



def open_pem(textbox):
    try:
        filePath = filedialog.askopenfilename(initialdir='./RSA-Utility',title='파일선택',filetypes=(('pem files','*.pem'),('all files','*.*')))
        textbox.insert(0,filePath)
    except:
        textbox.insert(0,'Error... try again')



def encrypt_pem(m, pem_file_path,label):
    rand = make_rand()
    filePath = os.path.dirname(os.path.realpath(__file__)) + '/' + rand + '_encrypt_data.txt'
    try:
        with open(pem_file_path,'r') as f:
            key = RSA.import_key(f.read())
            n = key.n
            e = key.e
        c = pow(int(m),int(e),int(n))

        with open(filePath,'w+') as f:
            f.write('enc_data : '+str(c))
        label.config(text='Encryption Success'+'\n')
    except:
        label.config(text='Encryption fail... try again')



def decrypt_pem(c, pem_file_path,label):
    rand = make_rand()
    filePath = os.path.dirname(os.path.realpath(__file__)) + '/' + rand + '_decrypt_data.txt'
    try:
        with open(pem_file_path,'r') as f:
            key = RSA.import_key(f.read())
            d = key.d
            n = key.n
        m = pow(int(c),int(d),int(n))

        with open(filePath,'w+') as f:
            f.write('dec_data : '+str(m))
        label.config(text='Decryption Success'+'\n')
    except:
        label.config(text='Decryption fail... try again')



def data_encrypt_number_window():
    instance_window = Toplevel()
    
    w = 500
    h = 150
    ws = instance_window.winfo_screenwidth()
    hs = instance_window.winfo_screenheight()
    x = (ws/2) - (w/2)
    y = (hs/2) - (h/2)
    plain_data = IntVar()
    n = IntVar()
    e = IntVar()

    instance_window.title("Encrypt data(number)")
    instance_window.geometry('%dx%d+%d+%d' % (w,h,x,y))
    instance_window.resizable(width=FALSE,height=FALSE)

    label1 = Label(instance_window,text='Enter the data to be encrypted(decimal)')
    label2 = Label(instance_window,text='Modulus(n)')
    label3 = Label(instance_window,text='Public Exponent(e)')
    label4 = Label(instance_window,text='')
    textbox1 = Entry(instance_window,width=30,textvariable=plain_data)
    textbox2 = Entry(instance_window,width=30,textvariable=n)
    textbox3 = Entry(instance_window,width=30,textvariable=e)
    button1 = Button(instance_window,text='encrypt data', command = lambda : encrypt(plain_data.get(),e.get(),n.get(),label4))
    label1.grid(column=0,row=0)
    textbox1.grid(column=1,row=0)
    label2.grid(column=0,row=1)
    textbox2.grid(column=1,row=1)
    label3.grid(column=0,row=2)
    textbox3.grid(column=1,row=2)
    button1.grid(column=1,row=3)
    label4.grid(column=1,row=4)



def data_encrypt_pem_window():
    instance_window = Toplevel()
    
    w = 530
    h = 150
    ws = instance_window.winfo_screenwidth()
    hs = instance_window.winfo_screenheight()
    x = (ws/2) - (w/2)
    y = (hs/2) - (h/2)
    plain_data = IntVar()
    file_path = StringVar()

    instance_window.title("Encrypt data(pem)")
    instance_window.geometry('%dx%d+%d+%d' % (w,h,x,y))
    instance_window.resizable(width=FALSE,height=FALSE)

    label1 = Label(instance_window,text='Enter the data to be encrypted(decimal)')
    label2 = Label(instance_window,text='PEM file')
    label3 = Label(instance_window,text='')
    textbox1 = Entry(instance_window,width=30,textvariable=plain_data)
    textbox2 = Entry(instance_window,width=30,textvariable=file_path)
    button1 = Button(instance_window,text='encrypt data', command = lambda : encrypt_pem(plain_data.get(),file_path.get(),label3))
    button2 = Button(instance_window,text='Browse...',command = lambda : open_pem(textbox2))
    label1.grid(column=0,row=0)
    textbox1.grid(column=1,row=0)
    label2.grid(column=0,row=1)
    textbox2.grid(column=1,row=1)
    button2.grid(column=2,row=1)
    label3.grid(column=1,row=2)
    button1.grid(column=1,row=3)

def convert_string_to_bytes(string,label):
    rand = make_rand()
    try:
        str_bytes = bytes(string.encode())
        res = bytes_to_long(str_bytes)
        filePath = os.path.dirname(os.path.realpath(__file__)) + '/' + rand + '_convert_bytes.txt'
        with open(filePath,'w+') as f:
            f.write('Convert bytes : '+str(res)+'\n')
        label.config(text='Convert Success')
    except:
        label.config(text='Convert fail... try again')
        

def convert_string_to_bytes_window():
    instance_window = Toplevel()
    
    w = 530
    h = 150
    ws = instance_window.winfo_screenwidth()
    hs = instance_window.winfo_screenheight()
    x = (ws/2) - (w/2)
    y = (hs/2) - (h/2)
    plain_string = StringVar()

    instance_window.title("Convert string to bytes")
    instance_window.geometry('%dx%d+%d+%d' % (w,h,x,y))
    instance_window.resizable(width=FALSE,height=FALSE)

    label1 = Label(instance_window,text='Enter the string to be converted')
    label2 = Label(instance_window,text='')
    textbox1 = Entry(instance_window,width=30,textvariable=plain_string)
    button1 = Button(instance_window,text='Convert', command = lambda : convert_string_to_bytes(plain_string.get(),label2))
    label1.grid(column=0,row=0)
    textbox1.grid(column=1,row=0)
    label2.grid(column=1,row=1)
    button1.grid(column=1,row=3)



def data_decrypt_number_window():
    instance_window = Toplevel()
    
    w = 500
    h = 150
    ws = instance_window.winfo_screenwidth()
    hs = instance_window.winfo_screenheight()
    x = (ws/2) - (w/2)
    y = (hs/2) - (h/2)
    enc_data = IntVar()
    d = IntVar()
    n = IntVar()

    instance_window.title("Decrypt data(number)")
    instance_window.geometry('%dx%d+%d+%d' % (w,h,x,y))
    instance_window.resizable(width=FALSE,height=FALSE)

    label1 = Label(instance_window,text='Enter the data to be decrypted(decimal)')
    label2 = Label(instance_window,text='Private Exponent(d)')
    label3 = Label(instance_window,text='Modulus(n)')
    label4 = Label(instance_window,text='')
    textbox1 = Entry(instance_window,width=30,textvariable=enc_data)
    textbox2 = Entry(instance_window,width=30,textvariable=d)
    textbox3 = Entry(instance_window,width=30,textvariable=n)
    button1 = Button(instance_window,text='decrypt data', command = lambda : decrypt(enc_data.get(),d.get(),n.get(),label4))
    label1.grid(column=0,row=0)
    textbox1.grid(column=1,row=0)
    label2.grid(column=0,row=1)
    textbox2.grid(column=1,row=1)
    label3.grid(column=0,row=2)
    textbox3.grid(column=1,row=2)
    button1.grid(column=1,row=3)
    label4.grid(column=1,row=4)



def data_decrypt_pem_window():
    instance_window = Toplevel()
    
    w = 530
    h = 150
    ws = instance_window.winfo_screenwidth()
    hs = instance_window.winfo_screenheight()
    x = (ws/2) - (w/2)
    y = (hs/2) - (h/2)
    plain_data = IntVar()
    file_path = StringVar()

    instance_window.title("Decrypt data(pem)")
    instance_window.geometry('%dx%d+%d+%d' % (w,h,x,y))
    instance_window.resizable(width=FALSE,height=FALSE)

    label1 = Label(instance_window,text='Enter the data to be decrypted(decimal)')
    label2 = Label(instance_window,text='PEM file')
    label3 = Label(instance_window,text='')
    textbox1 = Entry(instance_window,width=30,textvariable=plain_data)
    textbox2 = Entry(instance_window,width=30,textvariable=file_path)
    button1 = Button(instance_window,text='decrypt data', command = lambda : decrypt_pem(plain_data.get(),file_path.get(),label3))
    button2 = Button(instance_window,text='Browse...',command = lambda : open_pem(textbox2))
    label1.grid(column=0,row=0)
    textbox1.grid(column=1,row=0)
    label2.grid(column=0,row=1)
    textbox2.grid(column=1,row=1)
    button2.grid(column=2,row=1)
    label3.grid(column=1,row=2)
    button1.grid(column=1,row=3)



def convert_bytes_to_string(bytes,label):
    rand = make_rand()
    try:
        string = str(long_to_bytes(bytes))[2:-1]
        filePath = os.path.dirname(os.path.realpath(__file__)) + '/' + rand + '_convert_string.txt'
        with open(filePath,'w+') as f:
            f.write('Convert string : '+string+'\n')
        label.config(text='Convert Success')
    except:
        label.config(text='Convert fail... try again')



def convert_bytes_to_string_window():
    instance_window = Toplevel()
    
    w = 530
    h = 150
    ws = instance_window.winfo_screenwidth()
    hs = instance_window.winfo_screenheight()
    x = (ws/2) - (w/2)
    y = (hs/2) - (h/2)
    plain_bytes = IntVar()

    instance_window.title("Convert bytes to string")
    instance_window.geometry('%dx%d+%d+%d' % (w,h,x,y))
    instance_window.resizable(width=FALSE,height=FALSE)

    label1 = Label(instance_window,text='Enter the bytes to be converted')
    label2 = Label(instance_window,text='')
    textbox1 = Entry(instance_window,width=30,textvariable=plain_bytes)
    button1 = Button(instance_window,text='Convert', command = lambda : convert_bytes_to_string(plain_bytes.get(),label2))
    label1.grid(column=0,row=0)
    textbox1.grid(column=1,row=0)
    label2.grid(column=1,row=1)
    button1.grid(column=1,row=3)



def create_private_public_key(bit,label2):
    private_key = RSA.generate(bit)
    n = private_key.n
    p = private_key.p
    q = private_key.q
    e = private_key.e
    d = private_key.d
    u = private_key.u

    try:
        rand = make_rand()

        private_filePath = os.path.dirname(os.path.realpath(__file__)) + '/' + rand + '_' + 'private_key' + '.txt'

        f = open(private_filePath,'w+')
        f.write('p = '+str(p)+'\n\n')
        f.write('q = '+str(q)+'\n\n')
        f.write('n = '+str(n)+'\n\n')
        f.write('e = '+str(e)+'\n\n')
        f.write('d = '+str(d)+'\n\n')
        f.write('u = '+str(u)+'\n\n')
        f.close()

        public_filePath = os.path.dirname(os.path.realpath(__file__)) + '/' + rand + '_' + 'public_key' + '.txt'

        f = open(public_filePath,'w+')
        f.write('n = '+str(n)+'\n\n')
        f.write('e = '+str(e)+'\n\n')
        f.close()
        label2.config(text='private/public key generation Success') 
    except:
        label2.config(text='private/public key generation fail... try again') 
    


def Key_create_window_sep(var,button1,label2,bit):
    if bit == '':
        label2.config(text='not selected bit')
    elif var.get() == 1:
        button1.config(text='Create number key',command = lambda : create_private_public_key(int(bit),label2))

    elif var.get() == 2:
        button1.config(text='Create pem file',command = lambda : create_private_public_pem(int(bit),label2))



def Key_create_window():
    w = 500
    h = 100
    ws = window.winfo_screenwidth()
    hs = window.winfo_screenheight()
    x = (ws/2) - (w/2)
    y = (hs/2) - (h/2)


    instance_window = Toplevel()
    var = IntVar()
    instance_window.title("Create Key")
    instance_window.geometry('%dx%d+%d+%d' % (w,h,x,y))
    instance_window.resizable(width=FALSE,height=FALSE)

    global label1
    global label2
    global button1

    label1 = Label(instance_window,text='Choose your key size(bit)')
    label2 = Label(instance_window,text='')

    combo = Combobox(instance_window,state='readonly')
    combo['values'] = (1024,2048,4096)
    combo.grid(row=3,column=3)

    button1 = Button(instance_window, text='')

    pem_rb = Radiobutton(instance_window,text='.pem key', variable=var, value=2,command = lambda : Key_create_window_sep(var,button1,label2,combo.get()))
    num_rb = Radiobutton(instance_window,text='number key',variable=var, value=1,command = lambda : Key_create_window_sep(var,button1,label2,combo.get()))
    pem_rb.grid(row=4,column=4)
    num_rb.grid(row=3,column=4)
    label1.grid(row=3,column=2)
    button1.grid(row=4,column=3)
    label2.grid(row=5,column=3)



if __name__ == '__main__':

    window = Tk()

    w = 700
    h = 500
    ws = window.winfo_screenwidth()
    hs = window.winfo_screenheight()
    x = (ws/2) - (w/2)
    y = (hs/2) - (h/2)

    window.title("RSA Utility by.name2965")
    window.geometry('%dx%d+%d+%d' % (w,h,x,y))
    window.resizable(width=FALSE,height=FALSE)

    label = Label(window,text='RSA-Utility',font=('',25))
    HTML_label = HTMLLabel(window, html="<a href='https://github.com/name2965/RSA-Utility'> Github </a>",fg='blue')
    label.pack(expand=1)
    HTML_label.pack(expand=1)

    allMenu = Menu(window)

    menu1 = Menu(allMenu,tearoff=0)
    menu1.add_command(label ='Private/Public key',command=Key_create_window)
    allMenu.add_cascade(label='Create key',menu=menu1)

    menu2 = Menu(allMenu,tearoff=0)
    menu2.add_radiobutton(label='From .pem file',command=extract_key_window)
    allMenu.add_cascade(label='Extract key',menu=menu2)

    menu3 = Menu(allMenu, tearoff=0)
    menu3.add_radiobutton(label='Encrypt data(number key)',command=data_encrypt_number_window)
    menu3.add_radiobutton(label='Encrypt data(pem key)',command=data_encrypt_pem_window)
    menu3.add_radiobutton(label='Convert string to bytes',command=convert_string_to_bytes_window)
    allMenu.add_cascade(label='Encrypt',menu=menu3)

    menu4 = Menu(allMenu, tearoff=0)
    menu4.add_radiobutton(label='Decrypt data(number key)',command=data_decrypt_number_window)
    menu4.add_radiobutton(label='Decrypt data(pem key)',command=data_decrypt_pem_window)
    menu4.add_radiobutton(label='Convert bytes to string',command=convert_bytes_to_string_window)
    allMenu.add_cascade(label='Decrypt',menu=menu4)

    window.config(menu=allMenu)
    window.mainloop()