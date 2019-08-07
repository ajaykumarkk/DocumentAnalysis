#
#Author - Ajay Kumar K K
#
import sys, logging, optparse, re, os
from oletools import olevba
from oletools.olevba import TYPE2TAG
from oletools.thirdparty.xglob import xglob
from oletools import rtfobj

# 'AutoExec', 'AutoOpen', 'Auto_Open', 'AutoClose', 'Auto_Close', 'AutoNew', 'AutoExit',
# 'Document_Open', 'DocumentOpen',
# 'Document_Close', 'DocumentBeforeClose', 'Document_BeforeClose',
# 'DocumentChange','Document_New',
# 'NewDocument'
# 'Workbook_Open', 'Workbook_Close',
# *_Painted such as InkPicture1_Painted
# *_GotFocus|LostFocus|MouseHover for other ActiveX objects


re_autoexec = re.compile(r'(?i)\b(?:Auto(?:Exec|_?Open|_?Close|Exit|New)' +
						 r'|Document(?:_?Open|_Close|_?BeforeClose|Change|_New)' +
						 r'|NewDocument|Workbook(?:_Open|_Activate|_Close)' +
						 r'|\w+_(?:Painted|Painting|GotFocus|LostFocus|MouseHover' +
						 r'|Layout|Click|Change|Resize|BeforeNavigate2|BeforeScriptExecute' +
						 r'|DocumentComplete|DownloadBegin|DownloadComplete|FileDownload' +
						 r'|NavigateComplete2|NavigateError|ProgressChange|PropertyChange' +
						 r'|SetSecureLockIcon|StatusTextChange|TitleChange|MouseMove' +
						 r'|MouseEnter|MouseLeave))|Auto_Ope\b')

# MS-VBAL 5.4.5.1 Open Statement:
RE_OPEN_WRITE = r'(?:\bOpen\b[^\n]+\b(?:Write|Append|Binary|Output|Random)\b)'

re_write = re.compile(r'(?i)\b(?:FileCopy|CopyFile|Kill|CreateTextFile|'
	+ r'VirtualAlloc|RtlMoveMemory|URLDownloadToFileA?|AltStartupPath|WriteProcessMemory|'
	+ r'ADODB\.Stream|WriteText|SaveToFile|SaveAs|SaveAsRTF|FileSaveAs|MkDir|RmDir|SaveSetting|SetAttr)\b|' + RE_OPEN_WRITE)

# MS-VBAL 5.2.3.5 External Procedure Declaration
RE_DECLARE_LIB = r'(?:\bDeclare\b[^\n]+\bLib\b)'

re_execute = re.compile(r'(?i)\b(?:Shell|CreateObject|GetObject|SendKeys|'
	+ r'MacScript|FollowHyperlink|CreateThread|ShellExecuteA?|ExecuteExcel4Macro|EXEC|REGISTER)\b|' + RE_DECLARE_LIB)


class MacroRaptor(object):
	"""
	class to scan VBA macro code to detect if it is malicious
	"""
	def __init__(self, vba_code):
		self.vba_code = olevba.vba_collapse_long_lines(vba_code)
		self.autoexec = False
		self.write = False
		self.execute = False
		self.flags = ''
		self.suspicious = False
		self.autoexec_match = None
		self.write_match = None
		self.execute_match = None
		self.matches = []

	def scan(self):
		m = re_autoexec.search(self.vba_code)
		if m is not None:
			print("autoexec")
			self.autoexec = True
			self.autoexec_match = m.group()
			self.matches.append(m.group())
		m = re_write.search(self.vba_code)
		if m is not None:
			self.write = True
			self.write_match = m.group()
			self.matches.append(m.group())
		m = re_execute.search(self.vba_code)
		if m is not None:
			self.execute = True
			self.execute_match = m.group()
			self.matches.append(m.group())
		if self.autoexec and (self.execute or self.write):
			self.suspicious = True

	def get_flags(self):
		flags = ''
		flags += 'A' if self.autoexec else '-'
		flags += 'W' if self.write else '-'
		flags += 'X' if self.execute else '-'
		return flags

args = ["4.docm"]

for container, filename, data in xglob.iter_files(args, recursive=True,zip_password=None,zip_fname=None):
	# ignore directory names stored in zip files:
	if container and filename.endswith('/'):
		continue
	full_name = '%s in %s' % (filename, container) if container else filename
	print(full_name)
	if isinstance(data, Exception):
		print("Error occured")
	else:
		filetype = '???'
		try:
			vba_parser = olevba.VBA_Parser(filename=filename, data=data, container=container)
			filetype = TYPE2TAG[vba_parser.type]
		except Exception as e:
			print(e)
			continue
		if vba_parser.detect_vba_macros():
			vba_code_all_modules = ''
			try:
				for (subfilename, stream_path, vba_filename, vba_code) in vba_parser.extract_all_macros():
					vba_code_all_modules += vba_code + '\n'
			except Exception as e:
				print(e)
				continue
		mraptor = MacroRaptor(vba_code_all_modules)
		mraptor.scan()
		if mraptor.suspicious:
			print('Flags: A=AutoExec, W=Write, X=Execute')
			print("Flags: "+mraptor.get_flags()+" Filetype: "+filetype+" Full name: "+full_name)
			if mraptor.matches:
				print(mraptor.matches)
