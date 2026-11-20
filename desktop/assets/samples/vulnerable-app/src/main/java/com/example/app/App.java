package com.example.app;

/** Entry point: main -> InterpolatorService.interpolate -> vulnerable commons-text call. */
public class App {
    public static void main(String[] args) {
        String input = args.length > 0 ? args[0] : "hello ${sys:os.name}";
        System.out.println(new InterpolatorService().interpolate(input));
    }
}
