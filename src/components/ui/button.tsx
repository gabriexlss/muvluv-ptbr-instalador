import * as React from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap font-semibold cursor-pointer disabled:pointer-events-none disabled:opacity-45 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#3cc6ff]",
  {
    variants: {
      variant: {
        hero: "h-[50px] border-2 border-[#fff3c4] rounded-[5px] bg-gradient-to-b from-[#ffd459] to-[#f0b422] text-[#120d02] text-[14.5px] font-black tracking-[0.05em] shadow-[5px_5px_0_#b3780a] hover:brightness-105",
        side: "h-[50px] px-3.5 border-2 border-[#304469] rounded-[5px] bg-[#121a2d] text-[#dce8ff] text-[12.5px] font-semibold shadow-[4px_4px_0_rgba(0,0,0,0.5)] hover:bg-[#1a2540] hover:border-[#3cc6ff] hover:text-white",
        flat: "px-3 py-1.5 border-[1.5px] border-[#3cc6ff] bg-[#3cc6ff]/15 text-white text-[11.5px] font-bold rounded-[4px] hover:bg-[#3cc6ff]/25",
        win: "w-[30px] h-[28px] border-[1.5px] border-[#2c3b59] bg-[#131a2a] text-[#cfe0ff] rounded-[5px] hover:bg-[#1d2842] hover:border-[#3cc6ff] hover:text-white",
        winClose:
          "w-[30px] h-[28px] border-[1.5px] border-[#2c3b59] bg-[#131a2a] text-[#cfe0ff] rounded-[5px] hover:bg-rose-500/25 hover:border-rose-400 hover:text-rose-200",
      },
    },
    defaultVariants: {
      variant: "side",
    },
  }
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return (
      <Comp
        className={cn(buttonVariants({ variant, className }))}
        ref={ref}
        {...props}
      />
    );
  }
);
Button.displayName = "Button";
