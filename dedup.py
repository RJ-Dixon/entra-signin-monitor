def find_new_signins(signins, processed_ids):
    new_signins = []

    for signin in signins:
        if signin['id'] not in processed_ids:
            new_signins.append(signin)
            processed_ids.add(signin["id"])

    return new_signins