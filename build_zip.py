import zipfile
import glob

zip_file = "zips/GreyNoise.zip"
# create a ZipFile object
zipObj = zipfile.ZipFile(zip_file, "w", zipfile.ZIP_DEFLATED)
# Add multiple files to the zip
for file in glob.glob("ActionsDefinitions/*"):
    zipObj.write(file)
for file in glob.glob("ActionsScripts/*"):
    zipObj.write(file)
for file in glob.glob("Connectors/*"):
    zipObj.write(file)
for file in glob.glob("ConnectorsScripts/*"):
    zipObj.write(file)
for file in glob.glob("Dependencies/*"):
    zipObj.write(file)
for file in glob.glob("Managers/*"):
    zipObj.write(file)
zipObj.write("Integration-GreyNoise.def")
# close the Zip File
zipObj.close()
