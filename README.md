# IDA-Plugins
This repository will contains a collection of custom IDA Pro plugins, scripts, loaders, and utilities. These tools are designed to enhance the capabilities of IDA Pro for reverse engineering, debugging, and analysis tasks.

- Note: Im using IDA Pro *Version 7.6* so i recommend to use this plugins & loaders & scripts under this version.

## Usage
#### Loaders
1. Copy the loader python file into your `<IDA Directory>/loaders folder`.
2. Open IDA Pro.
3. Use a binary file (use the `example.bin` file) to test the loader, if the loader script is properly set up, IDA Pro will detect the file type and present the loader script as an option in the loading process.

#### Plugins
1. Copy the plugin Python file into your `<IDA Directory>/plugins` folder.
2. Open IDA Pro.
3. Verify the plugin setup by clicking on `Edit -> Plugins`, If you see the plugin name listed, it means the plugin is set up correctly.

#### Scripts
1. Place the script files in any directory of your choice.
2. Open IDA Pro.
3. Use the `File -> Script file...` menu option to browse and execute the script.
- Alternatively, you can execute scripts from the IDA Pro Python Console using:
```python
idaapi.load_and_run_plugin("script.py", 0)  
```

