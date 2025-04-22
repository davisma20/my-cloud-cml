import base64
import json
import sys

# Read JSON data from stdin
try:
    screenshot_data = json.load(sys.stdin)
    image_data_base64 = screenshot_data.get('ImageData')

    if not image_data_base64:
        print("Error: 'ImageData' not found in the input JSON.", file=sys.stderr)
        sys.exit(1)

    # Decode Base64
    image_data_bytes = base64.b64decode(image_data_base64)

    # Define output filename based on InstanceId
    instance_id = screenshot_data.get('InstanceId', 'unknown_instance')
    filename = f'console_screenshot_{instance_id}.jpg'

    # Write the decoded bytes to a JPEG file
    with open(filename, 'wb') as f:
        f.write(image_data_bytes)

    print(f"Screenshot saved to: {filename}")

except json.JSONDecodeError:
    print("Error: Invalid JSON input.", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"An error occurred: {e}", file=sys.stderr)
    sys.exit(1)
