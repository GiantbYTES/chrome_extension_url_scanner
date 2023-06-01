import os
import re
import json
from distutils.version import LooseVersion
import helper_funcs
from urllib.parse import urlparse
from PyQt5.QtWidgets import QApplication, QMainWindow, QTreeWidget, QTreeWidgetItem, QPushButton, QVBoxLayout, QHBoxLayout, QWidget, QLabel
from PyQt5.QtCore import QThread, pyqtSignal, QSize, QTimer, QCoreApplication
from PyQt5.QtGui import QColor,QBrush, QIcon, QMovie, QPixmap
from PyQt5 import uic, QtCore
import sys 
import subprocess
import threading
import getpass




#path to extensions
#IN FINAL VERSION PATH WILL BE "Default" instead of "Profile 1"
user = getpass.getuser()
profile = "Default"
extension_path = "/home/"+user+"/.config/google-chrome/Profile 1/Extensions" #TODO: if there's more than 1 profile in Chrome, then the "Default" dir gets replaced by profile num ("Profile 1" for example)
extension_path_dir = os.open(extension_path,os.O_RDONLY)


extension_folders = os.listdir(extension_path)
num_of_extensions = len(extension_folders) - 1 #not counting a built-in extension
if ("Temp" in extension_folders): num_of_extensions = num_of_extensions - 1
extension_percent = 100/(num_of_extensions)
ok_extensions = {}
suspicious_extensions = {}



#specific intel getter funcs:

#from manifest
def get_author(manifest_dict):
    return helper_funcs.search_json(manifest_dict,"author")

def get_version(manifest_dict):
    return helper_funcs.search_json(manifest_dict,"version")

def get_permissions_descriptions(manifest_dict):
    permissions_list = helper_funcs.search_json(manifest_dict,"permissions")
    return helper_funcs.compare_extension_permissions(permissions_list)

def get_extension_root(id):
    ext_id_folder = extension_path + "/" + id
    extension_version = os.listdir(ext_id_folder)
    if(extension_version.__contains__("Temp")): extension_version.remove("Temp") #remove temp folder so we only deal with extensions
    extension_version.sort(key=LooseVersion,reverse=True)
    return os.path.join(ext_id_folder,extension_version[0])

def get_manifest(id) : #returns the manifest (as json list)
    path_to_manifest = get_extension_root(id)
    manifest_file = open(os.path.join(path_to_manifest,"manifest.json"))
    manifest_dict = json.load(manifest_file)

    return manifest_dict



def get_list_of_extension_src_files(file_path):
    #relevant file formats to scan:
    extension_srcfiles_formats = [".html",".css",".js",".json"]
    #get list of all relevant files to scan
    files_to_scan = []
    for root, dirs , files in os.walk(file_path, topdown=True):
        for name in files:
            for format in extension_srcfiles_formats:
                if name.endswith(format):
                    files_to_scan.append(os.path.join(root, name))
    return files_to_scan



#filter list to get critical permissions specifically
def critical_permissions_extension(processed_permission_dict):
    critical_permissions_list = []
    for per in processed_permission_dict:
        if (processed_permission_dict[per]["risk"] == "critical"):
            critical_permissions_list.append(processed_permission_dict[per])
    return critical_permissions_list

    

def check_if_critical(list_of_blacklisted_urls,list_of_critical_permissions):
    if ((len(list_of_blacklisted_urls) == 0) and (len(list_of_critical_permissions) == 0)) : return False
    else: return True

#sub-scan-funcs

def in_file_ipv4(file,extension_version): #used to filter the version out of the ip list, in case the version matches the ip pattern
    content = file.read()
    pattern = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    ip_list = pattern.findall(content)
    for ip in ip_list[:]:
        if ip == "127.0.0.1": 
            ip_list.remove(ip)
            continue
        
        ip_elems = ip.split(".")
        for elem in ip_elems:
            if int(elem) > 255:
                if ip in ip_list:
                    ip_list.remove(ip)


    if extension_version in ip_list: ip_list.remove(extension_version) #here we remove the version from ip_list
    if "127.0.0.1" in ip_list: ip_list.remove("127.0.0.1")
    return ip_list

def in_file_url(file):
    content = file.read()
    #credit: https://uibakery.io/regex-library/url-regex-python
    pattern = re.compile("https?:\\/\\/(?:www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&\\/=]*)")
    pattern_list = pattern.findall(content)
    for i,e in enumerate(pattern_list): 
        if pattern_list[i].endswith('.'):
            pattern_list[i] = e[:-1]
    return pattern_list


 #As the name suggests, used for multithreaded blacklist scanning
class ScanThread(QThread): 
    scan_complete = pyqtSignal(list) #signals the end of the analysis
    update_progress = pyqtSignal(int) #signal to update first progress bar
    update_progress_2 = pyqtSignal(int)#signal to update second progress bar
    num_of_urls = None
    num_of_urls_percentage = None
    progress_of_urls = 0
    
 
    def run(self): 
        self.list = self.main()
        self.my_int = 0
        self.scan_complete.emit(self.list) 
        
    
    def scan_files(self,our_id,files_list,manifest_dict):
        extension_version = get_version(manifest_dict)
        list_of_domains=[]
        for file in files_list:
            file_handler = open(file,'r')
            list_of_urls = in_file_url(file_handler)
            list_of_processed_urls = []

            for url in list_of_urls:
                list_of_processed_urls.append(urlparse(url).netloc)
            list_of_domains.extend(list_of_processed_urls)
            file_handler.seek(0)
            list_of_ipv4s = in_file_ipv4(file_handler,extension_version)
            list_of_domains.extend(list_of_ipv4s)
            file_handler.seek(0)
            file_handler.close()
            

        #remove duplicates
        unique_domains=[]
        for processed_domain in list_of_domains:
            if processed_domain not in unique_domains:
                unique_domains.append(processed_domain)
        self.num_of_urls = len(unique_domains)
        self.num_of_urls_percentage = int(100/self.num_of_urls)



        
        for domain in unique_domains[:]:
            if domain == "127.0.0.1": unique_domains.remove(domain) #remove localhost
        # print(unique_domains)
        self.multithreading_check_urls_init(our_id,unique_domains)

    #running bash script which checks the domains against the blacklist
    def check_url_against_blacklists_func(self,our_id,url,semaphore): 
        output = subprocess.run(["./blcheck_lite",url], capture_output=True) 

        # print(output.stdout.decode()) 

        semaphore.release()
        self.progress_of_urls = int(self.progress_of_urls + self.num_of_urls_percentage)
        self.update_progress_2.emit(self.progress_of_urls)
        QtCore.QCoreApplication.processEvents()

        
    def multithreading_check_urls_init(self,our_id,url_list):
        threads = []
        semaphore = threading.Semaphore(30) #limit the amount of threads running
        for url in url_list:
            thread = threading.Thread(target=self.check_url_against_blacklists_func,args=(our_id,url,semaphore,))
            threads.append(thread)

        for thread in threads:
            semaphore.acquire()
            thread.start()
        for thread in threads:
            thread.join()
            

    def main(self):

        # extension_folders
        progress_of_extensions = 0
        extensions_id_to_name = {}
        
        #first we get all the names, otherwise the threaded approach of lumping all requests together creates conflicts
        for dir in extension_folders :
            # if dir in ["gighmmpiobklfepjocnamgkkbiglidom"]:

            # filtering out pre-installed extension and an edge case of empty temp folder
            if dir not in ["nmmhkkegccagdldgiimedpiccmgmieda","Temp"]:
                extensions_id_to_name[dir] = helper_funcs.get_name_from_id(dir)
        for dir in extension_folders :
            open("sus_domains.txt",'w').close()

            # if dir in ["gighmmpiobklfepjocnamgkkbiglidom"]:

            # filtering out pre-installed extension and an edge case of empty temp folder
            if dir not in ["nmmhkkegccagdldgiimedpiccmgmieda","Temp"]: 

                extension_name = extensions_id_to_name[dir]
                #manifest
                manifest_dict = get_manifest(dir)
                abs_extension_dir = get_extension_root(dir)
                files_list = get_list_of_extension_src_files(abs_extension_dir)
                self.scan_files(dir,files_list, manifest_dict)
                processed_permission_dict = get_permissions_descriptions(manifest_dict)
                # print (processed_permission_dict)


                progress_of_extensions = int(progress_of_extensions + extension_percent)
                self.update_progress.emit(progress_of_extensions)
                QtCore.QCoreApplication.processEvents()
                self.update_progress_2.emit(0)
                self.progress_of_urls = 0
                QtCore.QCoreApplication.processEvents()

                #manage extensions dictionary
                
                extension_version = get_version(manifest_dict)
                extension_author = get_author(manifest_dict)

                critical_permissions = critical_permissions_extension(processed_permission_dict)


                #COLLECTING SUSPICIOUS URLS
                sus_files = open("sus_domains.txt",'r')
                sus_urls = sus_files.readlines()
                for sus in sus_urls[:]:
                    sus[:-1]
                
                    
                if (check_if_critical(sus_urls,critical_permissions)): 
                    if len(sus_urls) < 1:
                        sus_urls = []
                    if len(critical_permissions) < 1:
                        critical_permissions = None
                    suspicious_extensions[dir] ={
                        "ID": extension_name,
                        "Author" : extension_author, 
                        "Version" : extension_version,
                        "Critical Permissions" : critical_permissions, 
                        "Suspicious URLs" : sus_urls
                        }
                    
                else:
                    ok_extensions[dir] = {
                        "ID": extension_name,
                        "Author" : extension_author, 
                        "Version" : extension_version
                        }

        list_dicts = [ok_extensions,suspicious_extensions]
        return list_dicts

            
 #this is our main window with the loading bars
class MainWindow(QMainWindow): 
    
    def __init__(self): 
        super().__init__() 
        uic.loadUi("Menu.ui", self) 
        self.ScanButton.clicked.connect(self.start_scan)
 
    def start_scan(self): 
        self.ScanButton.setEnabled(False)
        self.names = ['SCAN','SCAN.', 'SCAN..', 'SCAN...'] # setting up the "text loading" via array and updating it with a timer until the scan is complete
        self.index = 0
        self.timer = QTimer() 
        self.timer.timeout.connect(self.update_button_text) 
        self.timer.start(1000) # size in ms
        self.update_button_text()
        
        self.scan_thread = ScanThread() 
        self.scan_thread.update_progress_2.connect(self.updateProgress2)
        self.scan_thread.update_progress.connect(self.updateProgress)       
        self.scan_thread.scan_complete.connect(self.scan_complete) 
        self.scan_thread.start() 

    def update_button_text(self): 
        if self.index >= len(self.names): 
            self.index = 0 
        self.ScanButton.setText(self.names[self.index]) 
        self.index += 1

    def updateProgress(self,num):
        self.progressBar.setValue(num)


    def updateProgress2(self,num):
        self.progressBar_2.setValue(num)

    def scan_complete(self,list): 
        self.progressBar.setValue(100)
        self.timer.stop()
        self.ScanButton.setText("SCAN")
        dict_ok = list[0]
        dict_sus = list[1]
        self.new_window = ResultsWindow(dict_ok, dict_sus)
        self.new_window.show()
        print("Scan complete!") 

#this is our second window with the collected results
class ResultsWindow(QMainWindow):
    def __init__(self,dict_ok,dict_sus): 
        super().__init__()

        self.setWindowTitle('Results')
        self.button1 = QPushButton('Clean Extensions')
        self.button2 = QPushButton('Suspicious Extensions')
        self.button1.setIcon(QIcon("./icons8-protect-96.png")) #credit to icons8 for the icon
        self.button2.setIcon(QIcon("./icons8-warning-shield-96.png")) #credit to icons8 for the icon
        self.button1.setIconSize(QSize(32,32))
        self.button2.setIconSize(QSize(32,32))
        self.setGeometry(1,1,822,539)

        self.tree_widget1 = QTreeWidget()
        self.tree_widget2 = QTreeWidget()

        self.create_tree(self.tree_widget1, dict_ok, 'Clean Extensions')
        self.create_tree(self.tree_widget2, dict_sus, 'Suspicious Extensions')

        self.layout = QHBoxLayout()
        self.layout.addWidget(self.button1)
        self.layout.addWidget(self.button2)
        self.main_layout = QVBoxLayout()
        self.main_layout.addLayout(self.layout)
        self.main_layout.addWidget(self.tree_widget1)
        self.main_layout.addWidget(self.tree_widget2)


        self.central_widget = QWidget()
        self.central_widget.setLayout(self.main_layout)
        self.setCentralWidget(self.central_widget)

        self.button1.clicked.connect(self.show_tree_widget1)
        self.button2.clicked.connect(self.show_tree_widget2)
        self.tree_widget1.expanded.connect(self.handle_expanded)
        self.tree_widget2.expanded.connect(self.handle_expanded)
        self.tree_widget1.collapsed.connect(self.handle_collapsed)
        self.tree_widget2.collapsed.connect(self.handle_collapsed)

    #resizing columns when collapsed or expanded to fit the content below
    def handle_collapsed(self):
        self.tree_widget1.resizeColumnToContents(1)
        self.tree_widget2.resizeColumnToContents(1)
        self.tree_widget1.resizeColumnToContents(0)
        self.tree_widget2.resizeColumnToContents(0)

    def handle_expanded(self):
        self.tree_widget1.resizeColumnToContents(1)
        self.tree_widget2.resizeColumnToContents(1)
        self.tree_widget1.resizeColumnToContents(0)
        self.tree_widget2.resizeColumnToContents(0)

    #we create a tree for each category (clean/suspicious), and then a tree-widget-item for each extension
    def create_tree(self, tree_widget, dicti, name):
        tree_widget.setHeaderLabel(name)

        for key, value in dicti.items():
            id_of_ext = key 
            key = value["ID"]
            value["ID"] = id_of_ext
            item = QTreeWidgetItem()
            tree_widget.setHeaderLabels(["Extension", "Value"])
            item.setText(0, str(key))
            
            if isinstance(value, dict):
                for key2,value2 in value.items():
                    if(key2 =="Suspicious URLs" and value2!= None):
                        value2 = (''.join(value2))
                    elif(key2 =="Critical Permissions" and value2!= None):
                        temp = []
                        for kaki in value2:
                            name_of_per = str(kaki["name"])
                            description_of_per = str(kaki["description"])
                            temp.append(name_of_per+" ("+description_of_per+")")
                            value2 = ('\n'.join(temp))

                    QTreeWidgetItem(item,[key2, str(value2)]).setTextAlignment(0,0)

            
            tree_widget.addTopLevelItem(item)  
            self.tree_widget1.resizeColumnToContents(0)
            self.tree_widget2.resizeColumnToContents(0)
            self.tree_widget1.resizeColumnToContents(1)
            self.tree_widget2.resizeColumnToContents(1) 
            for i in range(tree_widget.topLevelItemCount()): 
                item = tree_widget.topLevelItem(i) 
                item.setBackground(0, QBrush(QColor(240, 240, 240)))


    def show_tree_widget1(self):
        self.tree_widget1.show()
        self.tree_widget2.hide()

    def show_tree_widget2(self):
        self.tree_widget1.hide() 
        self.tree_widget2.show()   



 
app = QApplication(sys.argv) 
window = MainWindow() 
window.show() 
sys.exit(app.exec_())

