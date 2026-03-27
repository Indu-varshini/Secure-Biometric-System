def hamming_similarity(template1, template2):
    """
    Computes Hamming similarity between two binary templates
    """
    if len(template1) != len(template2):
        return 0.0

    matches = sum(
        1 for a, b in zip(template1, template2) if a == b
    )

    return matches / len(template1)
