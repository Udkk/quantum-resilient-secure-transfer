package network;

public interface ProgressCallback {

    void onProgress(double progress);

    void onLog(String message);
}