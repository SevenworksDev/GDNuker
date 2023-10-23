import time, random, base64, hashlib, string
from itertools import cycle
from proxpy import request
from json import loads
from threading import Thread

proxyURL = input("HTTP Proxy List URL: ")
dlprox(proxyURL).get()
#with open('.proxpy-proxies', 'r+') as file: file.write(file.read().replace('\n\n', '\n'))

r = request()

b = "‎"
comInput = input("Comment (use ^^ in middle of word to filter bypass): ")
comment = comInput.replace("^^", b)

def infoget(file_path):
    gjuser = []
    gjpass = []
    gjaccid = []
    with open(file_path, 'r') as file:
        for line in file:
            homer, simpson, doh = line.strip().split(' / ')
            gjuser.append(homer)
            gjpass.append(simpson)
            gjaccid.append(doh)
    return gjuser, gjpass, gjaccid

gjuser, gjpass, gjaccid = infoget("accounts.txt")

def comment_chk(*,username,comment,levelid,percentage,type):
  part_1 = username + comment + levelid + str(percentage) + type + "xPT6iUrtws0J"
  return base64.b64encode(xor(hashlib.sha1(part_1.encode()).hexdigest(),"29481").encode()).decode()

def xor(data, key):
  return ''.join(chr(ord(x) ^ ord(y)) for (x,y) in zip(data, cycle(key)))

def gjp_encrypt(data):
  return base64.b64encode(xor(data,"37526").encode()).decode()

def gjcomment(name,passw,comment,level,accountid):
        try:
                gjp = gjp_encrypt(passw)
                c = base64.b64encode(comment.encode()).decode()
                chk = comment_chk(username=name,comment=c,levelid=str(level),percentage=0,type="0")
                data={
                    "secret":"Wmfd2893gb7",
                    "accountID":accountid,
                    "gjp":gjp,
                    "userName":name,
                    "comment":c,
                    "levelID":level,
                    "percent":0,
                    "chk":chk
                }
                r.load()
                resp = r.post("http://www.boomlings.com/database/uploadGJComment21.php",data=data,headers={"User-Agent": ""})
                if resp.isdigit():
                  print("Success - CommentID: "+resp)
                elif resp.startswith("temp_"):
                  print(f"{name} is banned for: {resp}")
                else:
                  # print(resp)
                  return None
        except:
                return None

def commands(level):
  st = ''.join(random.choice(string.ascii_letters) for _ in range(7))
  for i in range(len(gjuser)):
    gjcomment(gjuser[i], gjpass[i], comment, level, gjaccid[i])
    #gjcomment(gjuser[i], gjpass[i], f"{comment} {st}", level, gjaccid[i])

lvl=input("Level ID: ")
while 1:
    try:
        Thread(target=commands,args=(lvl,)).start()
    except:
        print(f"err")
