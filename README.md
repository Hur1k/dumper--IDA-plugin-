# dumper [IDA Pro Plugin]

First try at creating an IDA Pro plugin.

Just a simple plugin to dump memory from IDA Pro :D

## Installation

1. Copy the `dumper.py` file to your IDA Pro's `plugins` directory.

2. Restart IDA Pro.

## Usage

1. Open IDA Pro and load the target executable.

2. Run the plugin:
   - Open the "Edit" menu.
   - Select "Plugins" and then choose "dumper."

3. The plugin will prompt you to enter the following information:
   - Start address (hex)
   - End address (hex) or length (hex)
   - File path to save the dumped data

4. Click "OK" to execute the dump process.
