  from torfuncs import *
import consensus

error_codes ={

    0: "NONE",
    1: "PROTOCOL",
    2: "INTERNAL",       
    3: "REQUESTED", 
    4: "HIBERNATING",
    5: "RESOURCELIMIT",
    6: "CONNECTFAILED",   
    7: "OR_IDENTITY",   
    8: "OR_CONN_CLOSED", 
    9: "FINISHED",     
    10: "TIMEOUT",       
    11: "DESTROYED",     
    12: "NOSUCHSERVICE" 
}


relay_codes ={
	
         1: "RELAY_BEGIN",
         2: "RELAY_DATA",     
         3: "RELAY_END",       
         4: "RELAY_CONNECTED",
         5: "RELAY_SENDME",    
         6: "RELAY_EXTEND",    
         7: "RELAY_EXTENDED",  
         8: "RELAY_TRUNCATE", 
         9: "RELAY_TRUNCATED", 
        10: "RELAY_DROP",
        11: "RELAY_RESOLVE", 
        12: "RELAY_RESOLVED", 
        13: "RELAY_BEGIN_DIR",
        14: "RELAY_EXTEND2",   
        15: "RELAY_EXTENDED2", 
        32: "RELAY_COMMAND_ESTABLISH_INTRO",
        33: "RELAY_COMMAND_ESTABLISH_RENDEZVOUS",
        34: "RELAY_COMMAND_INTRODUCE1",
        35: "RELAY_COMMAND_INTRODUCE2",
        36: "RELAY_COMMAND_RENDEZVOUS1",
        37: "RELAY_COMMAND_RENDEZVOUS2",
        38: "RELAY_COMMAND_INTRO_ESTABLISHED",
        39: "RELAY_COMMAND_RENDEZVOUS_ESTABLISHED",
        40: "RELAY_COMMAND_INTRODUCE_ACK"

}

######## Custom error messages, gives the user a bit more infomation, as well as being easy to be changed and updated with them in a single file ################


def incorrect_key_len():
	print "Incorrect public key length, check to make sure correct value was passed"
	sys.exit("System exiting") # Exits here, no point carrying on as un correctable error has occured

def circId_cmd_error(circId, cmd):
	if cmd != 2: 
		print "Created cell was not recived"
		sys.exit("System exiting") # Exits here, no point carrying on as un correctable error has occured
	else:
		print "Circuit id recieved does not match the circuit id sent "
		sys.exit("System exiting") # Exits here, no point carrying on as un correctable error has occured

def destory_cell():
	print "Destory cell recieved, check the correct cell was sent previous and of the right format"
	sys.exit("System exiting") # Exits here, no point carrying on as un correctable error has occured

def circId_cmd3_error(circId, cmd):
	if cmd != 3: 
		print "Relay cell was not recived"
		sys.exit("System exiting") # Exits here, no point carrying on as un correctable error has occured
	else:
		print "Circuit id recieved does not match the circuit id sent "
		sys.exit("System exiting") # Exits here, no point carrying on as un correctable error has occured

def no_nodes():
	print "There are no nodes entered in the variable, please entere what nodes you wish to create the circuit with"
	sys.exit("System exiting")

def no_rendv_point():
	print "RELAY_COMMAND_RENDEZVOUS2EZVOUS_ESTABLISHED was not recieved, the node could possibly be down, try another one"
	sys.exit("System exiting")

def circuit_id_missmatch():
	print "Circuit Id recieved is not the same as expected"

def unnamed_error():
	print "Nickname unkown on the selected node, will try for another one now"


def introduce_padding_error():
	print "Padding is likely to have been done incorrectly, please check the RELAY_COMMAND_INTRODUCE1 cell  is formatted correctly"
	sys.exit("System exiting")

def incorrect_padding():
	print "Payload is not 509 in length, an error has occured during padding adding"

def no_relay_extend():
	print "Not a RELAY_EXTENDED cell recieved !"

def no_descriptor():
    print "No descriptor has been found, are you sure this hidden service exsits with this onion address ?"
    sys.exit("System exiting")

###############################################################################################
#### Converts the error messages in destroy cells to english errors to aid in debugging #######
###############################################################################################

#Converts the error message of the payload to the english version of that error
def error_type_to_message(err):
    # err = err[1] #Will be passed in format 
	# print err
	# print err[1]
	# print type(err[1])
    for (k,v) in error_codes.iteritems():
        if k == int(err[1]):
            print "Error message suggests the issue is: ",v
            return v
    raise IndexError("Error not known")

#Converts the relay command recieved to the english version to show the user what cell they recieved compared to what they was expecting
def relay_cmd_to_message(err):
    # err = err[1] #Will be passed in format 
	# print err
	# print err[1]
	# print type(err[1])
    for (k,v) in relay_codes.iteritems():
        if k == int(err):
            print "The recieved cell was not the same as expected, the application recieved a : ",v
        return v
    raise IndexError("Error not known")
