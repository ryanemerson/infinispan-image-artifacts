package org.infinispan.images;

public class NativeMainIT extends AbstractMainTest {

   @Override
   void execute(String... args) throws Exception {
      String[] cmd = new String[args.length + 1];
      cmd[0] = System.getProperty("native.image.path");
      System.arraycopy(args, 0, cmd, 1, args.length);
      Util.exec(cmd);
   }
}
