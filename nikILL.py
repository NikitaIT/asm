
import os
import subprocess

thisdir = os.getcwd()
print("thisdir", thisdir)
def fn(filename, dirpath, dirnames, filenames):
    """
        Args:
            filename (str): filename to check.
            dirpath (str): dirpath.
            dirnames (list): dirnames.
            filenames (list): filenames.
        Returns:
            (void): True if signature of the message is right otherwise False.
    """
    abs_path = os.path.join(dirpath, filename)
    print("scan file: ",  abs_path)
    with open(abs_path, 'rb') as f:
        s = f.read()
    if (s.find(
            b'x00P;\x05\x00\x00@<\x05\x00\x00\x80<\x05\x00\x00`>\x05\x00\x00\x80?\x05\x00\x00 @\x05\x00\x00\xb0A\x05\x00\x00\x90B\x05\x00\x00\xf0B\x05\x00\x00`E\x05\x00\x00\xb0E\x05\x00\x000F\x05\x00\x00`P\x05\x00\x00pT\x05\x00\x000]\x05\x00\x00\x90^\x05\x00\x00\x00f\x05\x00\x00`q\x05\x00\x00\xb0r\x05\x00\x00\x00\x7f\x05\x00\x00\xe0\x8f\x05\x00\x00\x10\x96\x05\x00\x00@\x96\x05\x00\x00\xa0\xdc\x05\x00\x00\x10\xdd\x05\x00\x00\x80\xdd\x05\x00\x00\xf0\xdd\x05\x00\x00P')):
        filename = filename.replace(".exe", ".txt")
        abs_pathTxt = os.path.join(dirpath, filename)
        if filename in filenames:
            print("txt file virused: ", abs_pathTxt)
            print("virus file detected: ", abs_path)
            print("remove virus file ...")
            subprocess.check_call(["attrib", "-H", abs_pathTxt])
            os.remove(abs_path)
            print("virus file removed, text file healed")
        # os.system(f"attrib -h {filename}")
    return True

for (dirpath, dirnames, filenames) in os.walk(thisdir):
    c = list(filter(lambda filename: filename.endswith('.exe'), filenames))
    list(map(lambda filename: fn(filename, dirpath, dirnames, filenames), c))
