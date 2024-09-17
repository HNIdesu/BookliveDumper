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
if not output_directory:
    output_directory=os.curdir
if not Path.exists(output_directory):
    os.makedirs(output_directory)
if not output_directory:
    output_directory=os.curdir

pid=frida.spawn(filepath)
session=frida.attach(pid)
script=session.create_script("""
const module=Module.load("WasabiDLL.dll")
	const WSB_MediaStream_GetSize=new NativeFunction(module.findExportByName("WSB_MediaStream_GetSize"),'pointer',['pointer','pointer'])
	const WSB_MediaStream_Seek=new NativeFunction(module.findExportByName("WSB_MediaStream_Seek"),'pointer',['pointer','int32','int32'])
	let url=null
	let do_dump=false
	function send_data(url,address,length){
		let bytesRead=0
		let index=0
		let chunkCount=Math.ceil(length/65536)
		while(bytesRead<length){
			const toRead=Math.min(65536,length-bytesRead)
			const chunk=address.add(bytesRead).readByteArray(toRead)
			send({url:url,chunkIndex:index++,chunkCount:chunkCount},chunk)
			bytesRead+=toRead
		}
	}
	Interceptor.attach(module.findExportByName("WSB_MediaStream_OpenUrl"),{
		onEnter:function(args){
			const url1=args[0].readCString()
			if(url1!=url){
				url=url1
				do_dump=true
			}else{
				do_dump=false//Avoid dumping the same file
			}
		}
	})
	Interceptor.attach(module.findExportByName("WSB_MediaStream_Read"),{
		onEnter:function(args){
			if(do_dump){
				const obj=args[0]
				WSB_MediaStream_Seek(obj,0,0)
				const ptr=Memory.alloc(4);
				WSB_MediaStream_GetSize(obj,ptr)
				this.length=ptr.readU32()
				this.out=Memory.alloc(this.length)
				args[1]=this.out
				args[2].writeU32(this.length)
			}
		},onLeave:function(){
			if(do_dump){
				send_data(url,this.out,this.length)
				do_dump=false
			}
			
		}
	})
""")

class CustomList[T]:
    def __init__(self,init_count:int) -> None:
        self.inner_list:list[T]=[None]*init_count
    def put_at(self,index:int,obj:T):
        if len(self.inner_list)<index+1:
            self.inner_list.extend([None] * (index + 1 - len(self.inner_list)))
        self.inner_list[index]=obj
    def count(self) -> int:
        count=0
        for item in self.inner_list:
            if item:count+=1
        return count
    def has_empty(self)->bool:
        for item in self.inner_list:
            if not item:return True
        return False
    
task_queue=Queue()
data_map=dict[str,CustomList[bytes]]()

def on_message(message:dict,data:bytes):
    if message["type"]=="send":
        url=message["payload"]["url"]
        index=message["payload"]["chunkIndex"]
        count=message["payload"]["chunkCount"]
        if not url in data_map:
            data_map[url]=CustomList[bytes](count)
        chunk_list=data_map[url]
        chunk_list.put_at(index,data)
        if not chunk_list.has_empty():
            task_queue.put((url,data_map.pop(url).inner_list))
script.on("message",on_message)
script.load()
frida.resume(pid)

while(True):
    (url,chunk_list)=task_queue.get()
    filename=url[url.rfind("/")+1:]
    savepath=Path.join(output_directory,filename)
    with open(savepath,"wb") as bw:
        for chunk in chunk_list:
            bw.write(chunk)
    print(f"dump file {Path.abspath(savepath)}")