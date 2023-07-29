## Editing JWTs

To edit a JWT using the JWT Editor extension:

1. Right-click the request with the JWT and select **Send to Repeater**.
2. In the request panel, go to the **JSON Web Token** tab.
3. Edit the JSON data as required in the **Header** and **Payload** fields.
4. Click **Sign**. A new dialog opens.
5. In the dialog, select the appropriate signing key, then click **OK**. The JWT is re-signed to correspond with the new values in the header and payload. If you haven't added a signing key, follow the instructions below.

## Adding a JWT signing key

To add a signing key to Burp using the JWT Editor extension:

1. Go to the **JWT Editor Keys** tab.
2. Click the button for the type of key that you want to add. For example, **New Symmetric Key**. A new dialog opens.
3. In the dialog, add the new key:
    - Click **Generate** to create a new key.
    - Alternatively, paste an existing key into the dialog.
4. Edit the key as required.
5. Click **OK** to save the key.