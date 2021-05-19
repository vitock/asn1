//
//  ViewController.m
//  OOD
//
//  Created by wei li on 2021/5/13.
//

#import "ViewController.h"
#import "ASN.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    UIButton *btn = [UIButton buttonWithType:UIButtonTypeCustom];
    
    [btn setTitleColor:[UIColor blueColor] forState:UIControlStateNormal];
    [btn setTitle:@"test" forState:UIControlStateNormal];
    btn.frame = CGRectMake(30, 130, 200, 40);
    btn.layer.borderWidth = 2;
    btn.layer.borderColor = [[UIColor redColor] CGColor];

    
    [self.view addSubview:btn];
    [btn addTarget:self  action:@selector(test:) forControlEvents:UIControlEventTouchUpInside];
    // Do any additional setup after loading the view.
}

- (void)test:(UIButton *)btn{
    BOOL  r = test2();
    static int j = 1;
    NSString *str = [NSString stringWithFormat:@"%@ :%d" ,r ? @"YES" :@"NO ", j ++ ];
    [btn setTitle:str forState:UIControlStateNormal];
    
}

@end
