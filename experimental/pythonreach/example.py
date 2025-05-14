# my_plotting_app/plot_generator.py
import matplotlib.pyplot as plt

def generate_and_save_plot(filename="my_plot.png"):
    """
    Generates a simple plot and saves it to a file.
    Matplotlib uses Pillow for handling various image formats and rendering
    quality (e.g., anti-aliasing) when saving plots.
    """
    print(f"Generating plot: {filename}...")
    # Save the plot to a file.
    # When saving to formats like PNG, JPEG, TIFF, etc., matplotlib often
    # uses Pillow for image encoding and processing.
    try:
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        print(f"Plot successfully saved as '{filename}'")
    except Exception as e:
        print(f"Error saving plot: {e}")
    finally:
        plt.close() # Close the plot to free up memory

if __name__ == "__main__":
    # Ensure the output directory exists if you plan to organize
    # For simplicity, saving in current directory here.
    generate_and_save_plot()