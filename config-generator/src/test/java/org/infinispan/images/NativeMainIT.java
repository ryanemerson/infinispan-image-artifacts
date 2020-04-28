package org.infinispan.images;

public class NativeMainIT extends AbstractMainTest {

   @Override
   int execute(String... args) throws Exception {
      String[] cmd = new String[args.length + 1];
      cmd[0] = System.getProperty("native.image.path");
      System.arraycopy(args, 0, cmd, 1, args.length);
      Process process = new ProcessBuilder().command(cmd).inheritIO().start();
      process.waitFor();
      return process.exitValue();
   }
}
