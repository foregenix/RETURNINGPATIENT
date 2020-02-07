# RETURNINGPATIENT
A long-haul purely DNS based command and control server/implant

# Requirements
- Python3. In order to run web2py you need a version < 3.8
- web2py (http://www.web2py.com/) . Download the source packet so that you can run it with Python3
- mono (https://www.mono-project.com)
- python libraries: pycryptodomex, netifaces, psutil, twisted

# Installation
1. Install mono
2. Install 3.5.8<python<3.8
3. Install the required python libraries:
```pip install pycryptodomex netifaces psutil twisted```
4. Download the web2py source code, unzip it and start the server with:
```python web2py.py```
5. From the web2py admin interface, upload web2py.app.ReturningPatient.w2p, name the application "ReturningPatient" and click Install
6. Edit the application and modify the mono and python3 paths right at the end of models/returningpatient.py
7. Click on the name of the application and login to the application with ```admin/changeme```
