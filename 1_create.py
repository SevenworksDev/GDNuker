import requests,random,string,time

print("Sevenworks Account Creator")
usernameInput = input("Username Prefix (Leave blank if you want only random characters): ")
nameString = int(input("Randomized String Length: "))

def create(gjuser, gjpass, gjemail):
  headers = { "User-Agent": "" }
  data = {
      "userName": gjuser,
      "password": gjpass,
      "email": gjemail,
      "secret": "Wmfv3899gc9"
  }
  req = requests.post("http://www.boomlings.com/database/accounts/registerGJAccount.php", data=data, headers=headers)
  print("Account Creator Status: "+req.text)

while True:
  myEmail = input("E-mail: ")
  f777 = ''.join(random.choices(string.ascii_letters, k=nameString))
  colbreakz = ''.join(random.choices(string.ascii_letters, k=7))
  myUsername = usernameInput+f777
  myPassword = colbreakz
  print("Creating User: "+myUsername)
  with open("accounts.txt", "a") as f:
      print(myUsername+" / "+myPassword+" / "+myEmail, file=f)
  create(myUsername, myPassword, myEmail)
