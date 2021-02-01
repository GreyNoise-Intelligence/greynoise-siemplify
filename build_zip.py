from zipfile import ZipFile

zip_file = 'zips/GreyNoise.zip'
# create a ZipFile object
zipObj = ZipFile(zip_file, 'w')
# Add multiple files to the zip
zipObj.write('ActionsDefinitions/')
zipObj.write('ActionsScripts/')
zipObj.write('Dependencies/')
zipObj.write('Integration-GreyNoise.def')
# close the Zip File
zipObj.close()
