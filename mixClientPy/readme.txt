使用说明：

1. 10.11需禁用System Integrity Protection（SIP）
  Reboot the Mac and hold down Command + R keys simultaneously after you hear the startup chime, this will boot OS X into Recovery Mode
  When the “OS X Utilities” screen appears, pull down the ‘Utilities’ menu at the top of the screen instead, and choose “Terminal”
  Type the following command into the terminal then hit return:
  csrutil disable; reboot

2. 启动fuzz 
  sudo python mixClientPy.py