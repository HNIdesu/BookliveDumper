import frida
from argparse import ArgumentParser
from queue import Queue
import os
import os.path as Path

parser=ArgumentParser()
parser.add_argument("executable_file_path",type=str)
parser.add_argument("-o","--output-directory",type=str)

args=parser.parse_args()
filepath=args.executable_file_path
output_directory=args.output_directory
if not Path.exists(output_directory):
    os.makedirs(output_directory)
if not output_directory:
    output_directory=os.curdir

pid=frida.spawn(filepath)
session=frida.attach(pid)
script=session.create_script("""
const module=Module.load("WasabiDLL.dll")
let url=""
Interceptor.attach(module.findExportByName("WSB_MediaStream_OpenUrl"),{
    onEnter:function(args){
        url=args[0].readCString()
    }
})
Interceptor.attach(module.findExportByName("WSB_MediaStream_Read"),{
    onEnter:function(args){
        this.obj=this.context.ecx
        this.out=args[1]
        this.length=args[2].readS32()
    },onLeave:function(){
        send({url:url},this.out.readByteArray(this.length))
    }
})
""")
task_queue=Queue()
def on_message(message:dict,data:bytes):
    if message["type"]=="send":
        url=message["payload"]["url"]
        task_queue.put((url,data))
script.on("message",on_message)  
script.load()
frida.resume(pid)

while(True):
    (url,data)=task_queue.get()
    filename=url[url.rfind("/")+1:]
    savepath=Path.join(output_directory,filename)
    with open(savepath,"wb") as bw:
        bw.write(data)
    print(f"dump file {savepath}")