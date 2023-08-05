/data/d1/jgwak1/STREAMLINED_DATA_GENERATION_MultiGraph_5BitPlusAdhocNodeAttr_JY/STEP_2_Benign_NON_TARGETTED_SUBGRAPH_GENERATION_GeneralLogCollection_subgraphs/model_v2/SecondStep.py




# RelativeName
RN2int()

# FileName
FN2int()

# daddr
address2dec()
v2o()



# Filename
def FN2int(filename):
      # return list  with 15 values
    filename = str(filename)
    new_list = [0] * 15
    if filename == 'None' or filename == '':
        new_list[0] = 1
    else: 
        new_list[14] = 1 # handle rest substrings in filename
        if "windows" in filename.lower():
            new_list[1] = 1
            new_list[14] = 0
        if "sys" in filename.lower():
            new_list[2] = 1
            new_list[14] = 0
        if '\\program files\\' in filename.lower():
            new_list[3] = 1
            new_list[14] = 0
        if "users" in filename.lower():
            new_list[4] = 1
            new_list[14] = 0
        if "logs" in filename.lower():
            new_list[5] = 1
            new_list[14] = 0
        if '\\ProgramData'.lower() in filename.lower():
            new_list[6] = 1
            new_list[14] = 0
        if "secure".lower() in filename.lower():
            new_list[7] = 1
            new_list[14] = 0
        if '\\DR0'.lower() in filename.lower(): #The device harddisk0 dr0 has a bad block indicates that there may be a bad block on your hard disk.
            new_list[8] = 1
            new_list[14] = 0
        if "Windows Defender Advanced Threat Protection".lower() in filename.lower():
            new_list[9] = 1
            new_list[14] = 0     
        if "securityhealthservice.exe".lower() in filename.lower():
            new_list[10] = 1
            new_list[14] = 0  
        if "CRYPTBASE".lower() in filename.lower():
            new_list[11] = 1
            new_list[14] = 0
        if "BCRYPT".lower() in filename.lower():
            new_list[12] = 1
            new_list[14] = 0
        if "NCRYPT".lower() in filename.lower() and "fsencryption".lower() not in filename.lower():
            new_list[13] = 1
            new_list[14] = 0
    return new_list 



# RelatvieName
def RN2int(RelativeName):
    # mul values 
    RelativeName = str(RelativeName)
    new_list = [0] * 20
    if RelativeName == 'None' or RelativeName == '':
        new_list[0]= 1
    else: 
        new_list[19] = 1 #rest of the substring in relativename
        # General info , Registry hierarchy depth 0
        if RelativeName.lower().find('registry') != -1:
            new_list[1] =1
            new_list[19] =0
            # General info , Registry hierarchy depth 1
        if RelativeName.lower().find('user') != -1:
            new_list[2] =1
            new_list[19] =0
        if RelativeName.lower().find('machine') != -1:
            new_list[3] =1
            new_list[19] =0
            # General info , Registry hierarchy depth 2 under machine
        if RelativeName.lower().find('software') != -1:
            new_list[4] =1
            new_list[19] =0
        if RelativeName.lower().find('system') != -1:
            new_list[5] =1
            new_list[19] =0
        # General info , Registry hierarchy depth 3 under software
        if RelativeName.lower().find('classes') != -1:
            new_list[6] =1
            new_list[19] =0

        # General info , Registry hierarchy depth 2 under user
        if "S-1-5-18" in RelativeName[0]:
            new_list[7] =1
            new_list[19] =0
        if  "S-1-5-19" in RelativeName[0]:
            new_list[8] =1
            new_list[19] =0
        if "S-1-5-20" in RelativeName[0]:
            new_list[9] =1
            new_list[19] =0
        if "S-1-5-21" in RelativeName[0]:
            new_list[10] =1
            new_list[19] =0
        if "S-1-5-22" in RelativeName[0]:
            new_list[11] =1
            new_list[19] =0
        if  "S-1-5-87" in RelativeName[0]:
            new_list[12] =1
            new_list[19] =0
        # general informatin, not in hierarchy
        if RelativeName[0] == "{EDD08927-9CC4-4E65-B970-C2560FB5C289}":
            new_list[13] =1
            new_list[19] =0
        if RelativeName[0] == "{70EB4F03-C1DE-4F73-A051-33D13D5413BD}":
            new_list[14] =1
            new_list[19] =0
        if RelativeName[0] == "{7DD42A49-5329-4832-8DFD-43D979153A88}":
            new_list[15] =1
            new_list[19] =0
        if RelativeName[0] == "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}":
            new_list[16] =1
            new_list[19] =0
        if RelativeName[0] == "Properties":
            new_list[17] =1
            new_list[19] =0
        # highlighting info which might help in classifying benign and malware 
        if RelativeName.lower().find('security') != -1:
            new_list[18] =1
            new_list[19] =0
                
        
    return new_list



# daddr
def address2dec(addr):
    if addr is None or addr == '':
        return 0
    else:
        if addr.find(':') == -1:
            temp = addr.split(".")
            x = int(temp[0])
            x2 = int(temp[1])
            x3 = int(temp[2])

            if x == 127:
                return 1
            if x == 10:
                return 2
            if x == 172 and x2 >= 16 and x2 <= 31:
                return 3
            if x == 192 and x2 == 168:
                return 4
    return 5

def v2o(value,length):
    fl = [0]*length
    if value < 0:
        return fl
    fl[value] = 1
    return fl











/data/d1/jgwak1/STREAMLINED_DATA_GENERATION_MultiGraph_5BitPlusAdhocNodeAttr_JY/STEP_3_processdata_traintestsplit/data_preprocessing/dp_v2_ONLY_TASKNAME_EDGE_ATTR/run_data_processor_MultiEdge_5BitPlusAdhocNodeAttr.py


Graph에서 순서 확인!


def run_data_processor(data_type : str, load_and_save_path: str):
    # [[3,0,0]] --- > 3 read consucutive events 

    # 0. initialize the dataprocessor class
    debug = True

    # for new graphs

    #node_attribute_list = [ 'FileName', 'FileObject', 'KeyObject', 'RelativeName', 'Win32StartAddr', 'daddr']
    # node_attribute_list = [] # testing- remove FileName attribute

    node_attribute_list = [ 'FileName', 'RelativeName', 'daddr' ] # testing- remove FileName attribute


    # edge_attribute_list = ['FileKey','FilePath', 'ImageBase', 'ImageName', 'Irp', 'Opcode', 'Task Name', 'sport', 'dport', 'saddr']

    #edge_attribute_list = ['Task Name','size', 'ImageSize', 'HandleCount',
    #                    'ReadOperationCount','WriteOperationCount',
    #                    'ReadTransferKiloBytes','WriteTransferKiloBytes','StatusCode',
    #                    'SubProcessTag','ProcessTokenElevationType',
    #                    'ProcessTokenIsElevated','MandatoryLabel','PackageRelativeAppId',
    #                    'Status','Disposition']  # total 16

    edge_attribute_list = ['Task Name']

    # JY @ 2023-05-20 : NO NEED TO CONCAT_EVENTS ANYMORE.
    concat_events = False  # will also concatonate events and take a frequency count 
    
    # JY @ 2023-05-20 : YES WE MAY STILL WANT THIS.
    compute_order = True  # will compute order for all events [1/#events, 2/#events, ...., #events/#events==1.0] 

    # JY @ 2023-05-20 : NO NEED TO CONCAT_EVENTS ANYMORE.
    # (X) A single edge = frequency count for all events + order-value of the first event seen
    # -> For Multi-Edge context, A single edge = bit-vector set for this event + order-value of this event across all events

    data_proc = DataProcessor(node_attribute_list=node_attribute_list, 
                              edge_attribute_list=edge_attribute_list, 
                              debug=debug)

    #load_path = '/data/d1/jgwak1/tabby/NEW_Projection3_Datasets_Based_On_Modified_CG_Code__20230124/GENERAL_LOG_COLLECTION_SUBGRAPHS_20230131'
    #save_path = '/data/d1/jgwak1/tabby/NEW_Projection3_Datasets_Based_On_Modified_CG_Code__20230124/GENERAL_LOG_COLLECTION_SUBGRAPHS_20230131'
    
    load_path = save_path = load_and_save_path

    # 1. process and save all benign samples
    if data_type == "Benign":
        print("\n>> Benign <<")
        process_all_graphs(data_type, load_path, save_path, data_proc, debug=debug, 
                           concat_events=concat_events, 
                           compute_order=compute_order)

    # 2. process and save all malware samples
    if data_type == "Malware":
        #print("\n>> Malware <<")
        process_all_graphs(data_type, load_path, save_path, data_proc, debug=debug, 
                           concat_events=concat_events, 
                           compute_order=compute_order)

    """
    def test():    