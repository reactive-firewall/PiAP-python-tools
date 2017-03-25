#! /usr/bin/python

INTERFACE_CHOICES=[u'wlan0', u'wlan1', u'wlan2', u'wlan3', u'eth0', u'eth1', u'eth2', u'eth3', u'lo', u'mon0', u'mon1']
""" whitelist of valid iface names """

def parseargs():
	"""Parse the arguments"""
	import argparse
	try:
		parser = argparse.ArgumentParser(description='Report the state of a given interface.', epilog='Basicly a python wrapper for ip show.')
		parser.add_argument('-i', '--interface', default=INTERFACE_CHOICES[1], choices=INTERFACE_CHOICES, help='The interface to use.')
		the_action = parser.add_mutually_exclusive_group(required=False)
		the_action.add_argument('-v', '--verbose', dest='verbose_mode', default=False, action='store_true', help='Enable verbose mode.')
		the_action.add_argument('-q', '--quiet', dest='verbose_mode', default=False, action='store_false', help='Disable the given interface.')
		theResult = parser.parse_args()
	except Exception as parseErr:
		parser.error(str(parseErr))
	return theResult

def taint_name(rawtxt):
	"""check the interface arguments"""
	tainted_input = str(rawtxt).lower()
	for test_iface in INTERFACE_CHOICES:
		if tainted_input in test_iface:
			return test_iface
	return None

def show_iface(iface_name="lo"):
	"""enable the given interface by calling ifup."""
	tainted_name = taint_name(iface_name)
	theResult = None
	import subprocess
	try:
		theResult = subprocess.check_output(['ip', 'addr', 'show', tainted_name], stderr=subprocess.STDOUT)
	except subprocess.CalledProcessError as subErr:
		theResult = None
	except Exception as cmdErr:
		print(str(cmdErr))
		print(str(cmdErr.args))
		theResult = "UNKNOWN"
	return theResult

def main():
	args = parseargs()
	try:
		interface = args.interface
		if args.verbose_mode is True:
			print(show_iface(interface))
			exit(0)
		else:
			status_txt = show_iface(interface)
			if status_txt is not None:
				if (" DOWN" in status_txt):
					print("DOWN")
				elif (" UP" in status_txt):
					print("UP")
				else:
					print("UNKNOWN")
			exit(0)
	except Exception as main_err:
		print(str("iface_check_status: REALLY BAD ERROR: ACTION will not be compleated! ABORT!"))
		print(str(main_err))
		print(str(main_err.args))
	exit(1)

if __name__ == '__main__':
	main()

