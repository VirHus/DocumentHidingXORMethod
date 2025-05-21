import wave
import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from xor_cipher import KEY, xor_encrypt
import time
from flask import flash, jsonify 

def hide_document_in_audio(audio_path, doc_path, output_audio):
    """Hides a document inside an audio file using LSB and XOR encryption."""
    start_time = time.time()  # ⏱️ Start timing
    try:
        file_extension = os.path.splitext(doc_path)[1]
        if not file_extension:
            return {"error": "No file extension found."}

        print(f"Encoding file with extension: {file_extension}")

        with open(doc_path, "rb") as file:
            doc_data = file.read()

        extension_bytes = (file_extension + "|||").encode()
        full_data = extension_bytes + doc_data
        encrypted_data = xor_encrypt(full_data, KEY)

        # Add these for bit size comparison
        original_bit_size = len(full_data) * 8  # bits before XOR
        encrypted_bit_size = len(encrypted_data) * 8  # bits after XOR
        
        with wave.open(audio_path, "rb") as audio:
            params = audio.getparams()
            frames = bytearray(audio.readframes(audio.getnframes()))
            original_amplitudes = np.frombuffer(frames, dtype=np.int16)

        if len(encrypted_data) * 8 > len(frames):
            print("Encoding failed:", str(e))  # Add this to your logs
            flash({"error": "Audio file too small to hide document."}), 500

        for i in range(len(encrypted_data)):
            byte = encrypted_data[i]
            for j in range(8):
                frames[i * 8 + j] = (frames[i * 8 + j] & 0xFE) | ((byte >> j) & 1)

        stego_amplitudes = np.frombuffer(frames, dtype=np.int16)

        timestamp = str(int(time.time()))
        histogram_path = os.path.join(os.path.dirname(output_audio), f"histogram_{timestamp}.png")

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 6))

        ax1.hist(original_amplitudes, bins=100, color='blue', alpha=0.7)
        ax1.set_title('Original Audio Amplitude Distribution')
        ax1.set_xlabel('Amplitude')
        ax1.set_ylabel('Frequency')
        ax1.grid(True, linestyle='--', alpha=0.5)

        ax2.hist(stego_amplitudes, bins=100, color='green', alpha=0.7)
        ax2.set_title('Stego Audio Amplitude Distribution')
        ax2.set_xlabel('Amplitude')
        ax2.set_ylabel('Frequency')
        ax2.grid(True, linestyle='--', alpha=0.5)

        plt.tight_layout()
        plt.savefig(histogram_path, dpi=150, bbox_inches='tight')
        plt.close()

        with wave.open(output_audio, "wb") as new_audio:
            new_audio.setparams(params)
            new_audio.writeframes(frames)

        elapsed_time = time.time() - start_time
        
        
        
        return {
            "status": "Success: Document hidden in audio.",
            "histogram_path": histogram_path,
            "elapsed_time": elapsed_time,
            "original_bits": original_bit_size,
            "encrypted_bits": encrypted_bit_size
        }


    except Exception as e:
        return {"error": f"Error during encoding: {str(e)}"}
