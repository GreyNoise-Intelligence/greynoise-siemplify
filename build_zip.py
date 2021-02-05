from zipfile import ZipFile

zip_file = "zips/GreyNoise.zip"
# create a ZipFile object
zipObj = ZipFile(zip_file, "w")
# Add multiple files to the zip
zipObj.write("ActionsDefinitions/")
zipObj.write("ActionsScripts/")
zipObj.write("Connectors/")
zipObj.write("ConnectorsScripts/")
zipObj.write("Dependencies/")
zipObj.write("Managers/")
zipObj.write("Integration-GreyNoise.def")
# close the Zip File
zipObj.close()
